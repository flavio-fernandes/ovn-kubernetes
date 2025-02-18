#!/usr/bin/env bash

# Helper usage
function usage() {
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "This script deploys a kind cluster and configures it to use Cilium as primary CNI, and OVN Kubernetes as secondary CNI."
  echo ""
  echo "Options:"
  echo "  BUILD_IMAGE=${BUILD_IMAGE:-true}        Set to true to build the Docker image instead of pulling it."
  echo "  OVN_INTERCONNECT=${OVN_INTERCONNECT:-false}  Set to false to use a non-interconnect deployment (values-no-ic.yaml)."
  echo ""
  echo "Example: BUILD_IMAGE=false OVN_INTERCONNECT=true $0"
  exit 1
}

# Default values for flags
BUILD_IMAGE=${BUILD_IMAGE:-true}
OVN_INTERCONNECT=${OVN_INTERCONNECT:-false}

# Determine the values file based on OVN_INTERCONNECT
if [[ "$OVN_INTERCONNECT" == "true" ]]; then
  VALUES_FILE="values-single-node-zone.yaml"
else
  VALUES_FILE="values-no-ic.yaml"
fi

# Verify dependencies
check_command() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 not found, please install it."; exit 1; }
}
check_command docker
check_command kubectl
check_command kind
check_command cilium  ; # see get_cilium_bin.sh

export DIR="$( cd -- "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  usage
fi

# IMG_PREFIX='ghcr.io/ovn-kubernetes/ovn-kubernetes/ovn-kube-fedora'
# TAG='master'
IMG_PREFIX='localhost/ovn-daemonset-f'
TAG='dev'
IMG="${IMG_PREFIX}:${TAG}"

if [[ "$BUILD_IMAGE" == "true" ]]; then
  check_command go # Only check for Go when building the image

  # Build image
  echo "Building Docker image..."

  # Build binaries
  make -C ${DIR}/../go-controller

  # Build image
  make -C ${DIR}/../dist/images IMAGE="${IMG}" OVN_REPO="" OVN_GITREF="" OCI_BIN="docker" fedora-image

else
  # Pull image from GitHub
  echo "Pulling Docker image..."
  docker pull ghcr.io/ovn-kubernetes/ovn-kubernetes/ovn-kube-fedora:master || {
     >&2 echo ghcr.io/ovn-kubernetes/ovn-kubernetes/ovn-kube-fedora:master not found. Maybe you should build the image.
     exit 1
  }
  docker tag ghcr.io/ovn-kubernetes/ovn-kubernetes/ovn-kube-fedora:master $IMG
fi

# Configure system parameters
# https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files
set -euxo pipefail
sudo sysctl fs.inotify.max_user_watches=1048576
sudo sysctl fs.inotify.max_user_instances=512

run_kubectl() {
  local retries=0
  local attempts=10
  while true; do
    if kubectl "$@"; then
      break
    fi

    ((retries += 1))
    if [[ "${retries}" -gt ${attempts} ]]; then
      echo "error: 'kubectl $*' did not succeed, failing"
      exit 1
    fi
    echo "info: waiting for 'kubectl $*' to succeed..."
    sleep 1
  done
}

start_cilium() {
    helm repo add cilium https://helm.cilium.io/ ||:

    # helm search repo cilium --versions --devel
    docker pull quay.io/cilium/cilium:v1.16.7
    kind load docker-image --name ovn quay.io/cilium/cilium:v1.16.7

    helm install cilium cilium/cilium --version 1.16.7 \
         --namespace kube-system \
         --set image.pullPolicy=IfNotPresent \
         --set ipam.mode=kubernetes \
         --set cni.exclusive=false

    cilium status --wait
}

install_multus() {
  local version="v4.1.3"
  echo "Installing multus-cni $version daemonset ..."
  wget -qO- "https://raw.githubusercontent.com/k8snetworkplumbingwg/multus-cni/${version}/deployments/multus-daemonset.yml" |\
    sed -e "s|multus-cni:snapshot|multus-cni:${version}|g" |\
    run_kubectl apply -f -
}

install_mpolicy_crd() {
  echo "Installing multi-network-policy CRD ..."
  mpolicy_manifest="https://raw.githubusercontent.com/k8snetworkplumbingwg/multi-networkpolicy/master/scheme.yml"
  run_kubectl apply -f "$mpolicy_manifest"
}

install_ipamclaim_crd() {
  echo "Installing IPAMClaim CRD ..."
  ipamclaims_manifest="https://raw.githubusercontent.com/k8snetworkplumbingwg/ipamclaims/v0.4.0-alpha/artifacts/k8s.cni.cncf.io_ipamclaims.yaml"
  run_kubectl apply -f "$ipamclaims_manifest"
}

kind_get_nodes() {
  kind get nodes --name "${kind_cluster_name}" | grep -v external-load-balancer
}

docker_create_second_disconnected_interface() {
  echo "adding second interfaces to nodes"
  local bridge_name="${1:-kindexgw}"
  echo "bridge: $bridge_name"

  # Create the network without subnets; ignore if already exists.
  docker network create --driver=bridge "$bridge_name" || true

  KIND_NODES=$(kind_get_nodes)
  for n in $KIND_NODES; do
    docker network connect "$bridge_name" "$n" || true
  done
}

enable_multi_net() {
  install_multus
  install_mpolicy_crd
  install_ipamclaim_crd
  docker_create_second_disconnected_interface "underlay"  # localnet scenarios require an extra interface
}

# Create a kind cluster
kind_cluster_name=ovn
kind delete clusters $kind_cluster_name || true
cat <<EOF | kind create cluster --name $kind_cluster_name --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  # image: nvcr.io/nv-ngn/sdn-dev/kind-node:v1.30.6
- role: worker
  # image: nvcr.io/nv-ngn/sdn-dev/kind-node:v1.30.6
- role: worker
  # image: nvcr.io/nv-ngn/sdn-dev/kind-node:v1.30.6
networking:
  # Instruct kind not to install its default CNI
  disableDefaultCNI: true

  # Note: cilium expects kubeProxyMode to be present
  # kubeProxyMode: none
EOF

start_cilium

kind load docker-image --name $kind_cluster_name $IMG
# Node labeling based on OVN_INTERCONNECT
if [[ "$OVN_INTERCONNECT" == "true" ]]; then
  for n in $(kind get nodes --name "${kind_cluster_name}"); do
    kubectl label node "${n}" k8s.ovn.org/zone-name=${n} --overwrite
  done
fi

enable_multi_net

# Deploy OVN Kubernetes as a secondary CNI using Helm
# Notice we will FUDGE UP a podNetwork, so ovn-kubernetes does not take over the
# real pod network, which is handled by another cni
cd ${DIR}/ovn-kubernetes
helm install ovn-kubernetes . -f ${VALUES_FILE} \
    --set k8sAPIServer="https://$(kubectl get pods -n kube-system -l component=kube-apiserver -o jsonpath='{.items[0].status.hostIP}'):6443" \
    --set podNetwork="10.254.0.0/16/24" \
    --set global.enableOvnKubeIdentity=false \
    --set global.enableEgressIp=false \
    --set global.enableEgressService=false \
    --set global.enableEgressFirewall=false \
    --set global.enableMultiExternalGateway=false \
    --set global.enableMultiNetwork=true \
    --set global.enableSecondaryCni=true \
    --set global.image.repository=${IMG_PREFIX} \
    --set global.image.tag=${TAG}

kubectl get pod -owide -A
${DIR}/wait_for_pods.sh -n ovn-kubernetes -l "app=ovnkube-node"

kubectl create -f ${DIR}/multi-net-test
sleep 3
kubectl get pods -n default -o custom-columns="NAME:.metadata.name,ANNOTATIONS:.metadata.annotations"
