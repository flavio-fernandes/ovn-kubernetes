#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
# set -x

# Default values
LABEL_SELECTOR=${LABEL_SELECTOR:-"name=multus"}
TIMEOUT=${TIMEOUT:-300s}
RETRY_INTERVAL=${RETRY_INTERVAL:-5}
MAX_RETRIES=${MAX_RETRIES:-60}  # 5 minutes (60 retries x 5 seconds)

# Get namespace from kubectl context if not provided
NAMESPACE=${NAMESPACE:-$(kubectl config view --minify --output 'jsonpath={..namespace}')}
NAMESPACE=${NAMESPACE:-kube-system}

usage() {
    cat <<EOF
Usage: $0 [options]
Options:
  -n <namespace>         Namespace to monitor (default: from kubectl context or kube-system)
  -l <label_selector>    Label selector to identify pods (default: name=multus)
  -t <timeout>           Timeout for kubectl wait (default: 300s)
  -i <interval>          Interval between retries to check pod existence (default: 5 seconds)
  -r <retries>           Max retries for checking pod existence (default: 60)
EOF
}

# Parse arguments
while getopts "n:l:t:i:r:h" opt; do
    case $opt in
        n) NAMESPACE=$OPTARG ;;
        l) LABEL_SELECTOR=$OPTARG ;;
        t) TIMEOUT=$OPTARG ;;
        i) RETRY_INTERVAL=$OPTARG ;;
        r) MAX_RETRIES=$OPTARG ;;
        h) usage; exit 0 ;;
        *) usage; exit 1 ;;
    esac
done

echo "Waiting for pods with label $LABEL_SELECTOR in namespace $NAMESPACE to be created..."

# Check if pods exist
for ((i=1; i<=MAX_RETRIES; i++)); do
    if kubectl -n "$NAMESPACE" get pods -l "$LABEL_SELECTOR" &>/dev/null; then
        echo "Pods found. Proceeding to wait for readiness..."
        break
    fi
    echo "No pods found yet. Retrying in $RETRY_INTERVAL seconds... ($i/$MAX_RETRIES)"
    sleep "$RETRY_INTERVAL"
done

# If no pods are found after retries, exit with an error
if ! kubectl -n "$NAMESPACE" get pods -l "$LABEL_SELECTOR" &>/dev/null; then
    echo "Error: Pods with label $LABEL_SELECTOR were not created within the expected time." >&2
    exit 1
fi

# Wait for pods to be ready
kubectl -n "$NAMESPACE" wait --for=condition=ready pod -l "$LABEL_SELECTOR" --timeout="$TIMEOUT"

