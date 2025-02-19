
# OVN Kubernetes as Secondary CNI with Cilium as Primary CNI

This experimental branch demonstrates the use of **OVN Kubernetes** as a **secondary CNI** while **Cilium** is set up as the primary CNI in a Kubernetes cluster. The goal is to enable multiple CNIs in a Kubernetes setup, where Cilium handles the primary network, and OVN Kubernetes takes on the secondary network role without interfering with the primary CNI.

## Key Concept: Deception of Pod Network

A key element for accomplishing this task is to **deceive** the system about the pod network. This is necessary so that **OVN Kubernetes** does not perform a hostile takeover of the **CIDR** range that we want **Cilium** (the external primary CNI) to handle. We also use specific flags to enable **OVN Kubernetes** as a runtime secondary CNI.

### Quickstart

```bash
$ git clone https://github.com/flavio-fernandes/ovn-kubernetes.git -b multicni &&
  cd ovn-kubernetes/helm
$ ./get_cilium_bin.sh 
$ ./deploy_ovn_as_secondary_cni.sh
```
    
### Feature Flag for Enabling Secondary CNI

To make OVN Kubernetes function as a secondary CNI, a new flag called `enable-secondary-cni` is used. This flag can be set to feature-gate **OVN Kubernetes** as a secondary CNI within the Kubernetes cluster.

You can enable this feature using the following methods:

1. **Via `kind` script flags:**
   Use the `-sce` or `--secondary-cni-enable` flags when running the Kind setup scripts:

   ```bash
   kind.sh -sce
   kind-helm.sh -sce
   ```

2. **Via exported shell variable:**
   You can also enable the secondary CNI by exporting the `OVN_SECONDARY_CNI_ENABLE` environment variable before running the script:

   ```bash
   OVN_SECONDARY_CNI_ENABLE=true kind.sh
   ```

   This will treat all the pods in the primary network as **host-networked pods**, ensuring that the secondary CNI (OVN Kubernetes) doesn't interfere with the primary CNI (Cilium).

---

## ASCII Cinema Recording

To visualize the setup process, here's an ASCII cinema recording demonstrating how the configuration works:

[![asciicast](https://asciinema.org/a/704410.svg)](https://asciinema.org/a/704410)

This recording shows the process of configuring the secondary CNI, deploying OVN Kubernetes alongside Cilium, and verifying that the pod network behaves as expected.

---
