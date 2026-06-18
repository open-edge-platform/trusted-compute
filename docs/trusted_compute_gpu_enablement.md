# GPU Enablement in Trusted Compute Environment

This document provides a step-by-step guide to enable GPU passthrough in a Trusted Compute environment. It includes instructions for GPU driver management and running a sample application.
## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [GPU Driver Management](#gpu-driver-management)
- [Install Trusted Compute Package](#install-trusted-compute-package)
- [Deploy sample application](#deploy-sample-application)
- [Pod Deployment and Verification](#pod-deployment-and-verification)
- [Revert GPU Binding](#revert-gpu-binding)

## Overview

### What is GPU Passthrough?

GPU passthrough allows a virtual machine to directly access a physical GPU, bypassing the host operating system’s drivers. By leveraging VFIO (Virtual Function I/O), the GPU is securely assigned to the VM, enabling workloads inside the Trusted Compute environment to utilize the GPU with minimal overhead and near-native performance. This is essential for compute-intensive applications, such as AI/ML inference or graphics workloads, in a trusted and isolated environment.

## Prerequisites

### Hardware Requirements

- Intel CPU with virtualization support (VT-x and VT-d)
- Intel integrated GPU (tested on Asus PE3000G EN)
- IOMMU enabled in BIOS/UEFI

### Software Requirements

- Kubernetes or K3s cluster
- Trusted Compute version 1.5.1 or newer
- Linux kernel with:
   - IOMMU enabled
   - VFIO support
   - DRM/i915 or xe driver support

## GPU Driver Management

To enable GPU passthrough, use the `intel-igpu-vfio-bind.sh` script included in the Trusted Compute installation package under the `tools/` directory. The script automatically detects the Intel iGPU, binds it to the `vfio-pci` driver, and generates a CDI spec at `/etc/cdi/intel-igpu-tc-cdi.yaml`.

#### 1. Bind GPU to vfio-pci

> **Note:** Binding the GPU to `vfio-pci` will stop the display manager and disable the graphical display on the host. It is recommended to run this step over SSH. The display will be restored after running the `unbind` command.

```bash
sudo ./tools/intel-igpu-vfio-bind.sh bind
```

The script will:
- Auto-detect the Intel iGPU PCI address and device ID
- Stop the display manager
- Unbind the GPU from its native driver (`i915` or `xe`)
- Bind the GPU to `vfio-pci`
- Generate a CDI spec at `/etc/cdi/intel-igpu-tc-cdi.yaml` with the correct VFIO and DRI device nodes

#### 2. Verify VFIO Binding

```bash
$ ls /dev/vfio
# Expected: vfio  <n>  (control file + one or more IOMMU group numbers)

$ lspci -nnk | grep -A4 -E '(VGA|Display).*Intel'
# Kernel driver in use: vfio-pci
```

## Install Trusted Compute Package


#### 1. Install on Edge Manageability Framework (EMF) Cluster

1. **Set up the EMF cluster:**  
  Follow the [Edge Infrastructure Setup Guide](https://docs.openedgeplatform.intel.com/edge-manage-docs/3.1/user_guide/set_up_edge_infra/index.html) to prepare your EMF cluster.

2. **Deploy the Trusted Compute package:**  
  Refer to the [Trusted Compute Package Deployment Guide](https://docs.openedgeplatform.intel.com/edge-manage-docs/3.1/user_guide/package_software/extensions/trusted_compute_package.html#deploy-trusted-compute-package) for deployment instructions.

3. **Access the EMF cluster from your local machine:**  
  Use the `kubeconfig.yaml` file downloaded from the EMF cluster to configure access from your local environment.  
  For detailed steps, refer to [Organize Cluster Access with a Kubeconfig File](https://docs.openedgeplatform.intel.com/edge-manage-docs/3.1/user_guide/set_up_edge_infra/clusters/accessing_clusters.html).

#### 2. Install on Standalone System

  Follow the [Trusted Compute k3s Installation on Standalone Ubuntu Edge Node](https://github.com/open-edge-platform/trusted-compute/blob/main/docs/trusted_compute_baremetal.md) guide for instructions on installing Trusted Compute on a standalone system.

## Deploy Sample Application

GPU passthrough can be verified by deploying [an OpenCL image](https://github.com/intel/intel-device-plugins-for-kubernetes/tree/v0.36.0/demo/intel-opencl-icd) which runs **clinfo**, outputting the GPU capabilities detected by the driver installed in the image.

#### 1. Make the image available to the cluster

Clone and build the image:
```bash
# Use the desired release tag or main
$ git clone https://github.com/intel/intel-device-plugins-for-kubernetes -b v0.36.0
$ cd intel-device-plugins-for-kubernetes
$ make intel-opencl-icd

# Tag and push the intel-opencl-icd image to a repository available in the cluster
$ docker tag intel/intel-opencl-icd:0.36.0 <repository>/intel-opencl-icd:0.36.0
$ docker push <repository>/intel-opencl-icd:0.36.0
```

#### 2. Preparing Pod Annotations

After running `intel-igpu-vfio-bind.sh bind`, the CDI spec is generated at `/etc/cdi/intel-igpu-tc-cdi.yaml`. Add the following annotations to your pod specification to enable GPU passthrough:

- `default_memory`: Minimum memory (in MB) for the Kata VM. At least 4096 MB required.
- `pcie_root_port`: Number of PCIe root ports for device hot-plug. Minimum value is `1`.
- `hot_plug_vfio`: Enables hot-plugging of VFIO devices to the PCIe root port.
- `enable_virtio_mem`: Enables virtio-mem for dynamic memory management in the VM.
- `cdi-devices.noderesource.dev/container.<container-name>`: References the CDI device by kind and name.

Refer to the sample application pod specification below for a complete example.

## Pod Specification for sample application

Create a pod specification with proper GPU device annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: intel-opencl-icd
  annotations:
    io.katacontainers.config.hypervisor.default_memory: "4096"
    io.katacontainers.config.hypervisor.pcie_root_port: "1"
    io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
    io.katacontainers.config.hypervisor.enable_virtio_mem: "true"
    cdi-devices.noderesource.dev/container.intel-opencl-icd: |
      - gpu.intel.com/igpu=tc
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  containers:
  - name: intel-opencl-icd
    image: <repository>/intel-opencl-icd:0.36.0  # update based on your repository
    imagePullPolicy: Always
    resources: # modify as per your requirement
      requests:
        cpu: 1
        memory: "2Gi"
      limits:
        cpu: 2
        memory: "4Gi"
```

## Pod Deployment and Verification

Save the pod specification to a file (e.g., `opencl-pod.yaml`) and deploy it:

```bash
$ kubectl apply -f opencl-pod.yaml
```

After deploying the `intel-opencl-icd` pod, verify GPU access by exec-ing into the container and running `clinfo`:

```bash
$ kubectl exec -it intel-opencl-icd -- clinfo
```

If GPU passthrough is successful, `clinfo` will display the detected GPU and its OpenCL capabilities. If the GPU is not detected, review the previous steps to ensure the GPU is bound to `vfio-pci` and the CDI annotation is correct.

## Revert GPU Binding

After you are done using GPU passthrough, use the same script to restore the GPU to its native driver so the host regains GPU access.

```bash
sudo ./tools/intel-igpu-vfio-bind.sh unbind
```

The script will:
- Detect the native driver (`i915` or `xe`) via the GPU's kernel modalias
- Unbind the GPU from `vfio-pci`
- Rebind to the native driver
- Restart the display manager

```bash
# Verify the GPU is restored to the native driver:
lspci -nnk | grep -A4 -E '(VGA|Display).*Intel'
# Output should show:
# Kernel driver in use: i915  (or `xe`, depending on platform/kernel)
```

This restores the GPU to its original state for use by the host system.