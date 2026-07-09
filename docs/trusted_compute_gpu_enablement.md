# GPU Enablement in Trusted Compute Environment

This document provides a step-by-step guide to enable GPU passthrough in a Trusted Compute environment. It includes instructions for GPU driver management and running a sample application.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Install Trusted Compute Package](#install-trusted-compute-package)
- [GPU Driver Management](#gpu-driver-management)
  - [Bind GPU to vfio-pci](#bind-gpu-to-vfio-pci)
  - [Verify VFIO Binding](#verify-vfio-binding)
- [Deploy Sample Application](#deploy-sample-application)
  - [Build and Push the Image](#build-and-push-the-image)
  - [Deploy with K3s](#deploy-with-k3s)
  - [Deploy with Docker Compose](#deploy-with-docker-compose)
- [Revert GPU Binding](#revert-gpu-binding)

## Overview

GPU passthrough allows a virtual machine to directly access a physical GPU, bypassing the host operating system's drivers. By leveraging VFIO (Virtual Function I/O), the GPU is securely assigned to the VM, enabling workloads inside the Trusted Compute environment to utilize the GPU with minimal overhead and near-native performance. This is essential for compute-intensive applications such as AI/ML inference or graphics workloads in a trusted and isolated environment.

## Prerequisites

- Intel CPU with VT-x/VT-d support and integrated GPU
- IOMMU enabled in BIOS/UEFI and Linux kernel with VFIO, DRM/i915 or xe driver support
- Kubernetes, K3s, or Docker with Trusted Compute version 1.5.2 or newer

## Install Trusted Compute Package

Follow the [Trusted Compute k3s Installation on Standalone Ubuntu Edge Node](https://github.com/open-edge-platform/trusted-compute/blob/main/docs/trusted_compute_baremetal.md) guide for instructions on installing Trusted Compute on a standalone system.

> **Note:** During the Trusted Compute installation, you will set up either K3s or Docker. Follow the corresponding deployment section in this guide based on which option you chose during installation.

## GPU Driver Management

To enable GPU passthrough, use the `intel-igpu-vfio-bind.sh` script located in the `tools/` directory of the Trusted Compute installation package used in the previous step. The script automatically detects the Intel iGPU, binds it to the `vfio-pci` driver, and generates a CDI spec at `/etc/cdi/intel-igpu-tc-cdi.yaml`.

### Bind GPU to vfio-pci

> **Note:** Binding the GPU to `vfio-pci` will stop the display manager and disable the graphical display on the host. It is recommended to run this step over SSH. The display will be restored after running the `unbind` command.

```bash
sudo ./tools/intel-igpu-vfio-bind.sh bind
```

The script auto-detects the Intel iGPU, stops the display manager, unbinds the GPU from its native driver (`i915` or `xe`), binds it to `vfio-pci`, and generates a CDI spec at `/etc/cdi/intel-igpu-tc-cdi.yaml`.

### Verify VFIO Binding

```bash
$ ls /dev/vfio
# Expected: vfio  <n>  (control file + one or more IOMMU group numbers)

$ lspci -nnk | grep -A4 -E '(VGA|Display).*Intel'
# Kernel driver in use: vfio-pci
```

## Deploy Sample Application

GPU passthrough can be verified by deploying [an OpenCL image](https://github.com/intel/intel-device-plugins-for-kubernetes/tree/v0.36.0/demo/intel-opencl-icd) which runs **clinfo**, outputting the GPU capabilities detected by the driver installed in the image.

> **Note:** Follow either the K3s or Docker Compose deployment section below based on your installation.

### Build and Push the Image

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

### Deploy with K3s

Create a pod specification with proper GPU device annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: intel-opencl-icd
  annotations:
    # Required for GPU passthrough
    io.katacontainers.config.hypervisor.default_memory: "4096"
    io.katacontainers.config.hypervisor.pcie_root_port: "1"
    io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
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

Deploy and verify:

```bash
# Deploy the pod
$ kubectl apply -f opencl-pod.yaml

# Verify GPU access
$ kubectl exec -it intel-opencl-icd -- clinfo
```

If GPU passthrough is successful, `clinfo` will display the detected GPU and its OpenCL capabilities. If the GPU is not detected, review the previous steps to ensure the GPU is bound to `vfio-pci` and the CDI annotation is correct.

### Deploy with Docker Compose

For Docker deployments, create a `docker-compose.yml` file:

```yaml
services:
  intel-opencl-icd:
    image: <repository>/intel-opencl-icd:0.36.0
    runtime: io.containerd.kata.v2
    # Required for GPU passthrough
    annotations:
      io.katacontainers.config.hypervisor.default_memory: "4096"
      io.katacontainers.config.hypervisor.pcie_root_port: "1"
      io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
    devices:
      - /dev/vfio/<n>:/dev/vfio/<n>  # Replace <n> with your IOMMU group number
    volumes:
      - /dev:/dev
```

Deploy and verify:

```bash
# Start the container
$ docker compose up -d

# Verify GPU access
$ docker compose exec intel-opencl-icd clinfo
```

If GPU passthrough is successful, `clinfo` will display the detected GPU and its OpenCL capabilities.

## Revert GPU Binding

After you are done using GPU passthrough, use the same script to restore the GPU to its native driver so the host regains GPU access.

```bash
sudo ./tools/intel-igpu-vfio-bind.sh unbind
```

The script detects the native driver (`i915` or `xe`), unbinds the GPU from `vfio-pci`, rebinds to the native driver, restarts the display manager, and restores the GPU to its original state for use by the host system.

```bash
# Verify the GPU is restored to the native driver:
lspci -nnk | grep -A4 -E '(VGA|Display).*Intel'
# Output should show:
# Kernel driver in use: i915  (or `xe`, depending on platform/kernel)
```