# GPU Enablement in Trusted Compute Environment
This document provides a step-by-step guide to enable GPU passthrough in a Trusted Compute environment using Kata Containers. It includes instructions for GPU driver management and running a sample application.
## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [GPU Driver Management](#gpu-driver-management)
- [Install Trusted Compute Package](#install-trusted-compute-package)
- [Deploy sample application](#deploy-sample-application)
- [Pod Deployment and Verification](#4-pod-deployment-and-verification)
- [Revert GPU Binding](#5-revert-gpu-binding)

## Overview

### What is GPU Passthrough?

GPU passthrough allows a virtual machine to directly access a physical GPU, bypassing the host operating system’s drivers. By leveraging VFIO (Virtual Function I/O), the GPU is securely assigned to the VM, enabling workloads inside Kata Containers to utilize the GPU with minimal overhead and near-native performance. This is essential for compute-intensive applications, such as AI/ML inference or graphics workloads, in a trusted and isolated environment.

## Prerequisites

### Hardware Requirements

- Intel CPU with virtualization support (VT-x and VT-d)
- Intel integrated GPU (tested on Asus PE3000G EN)
- IOMMU enabled in BIOS/UEFI

### Software Requirements

- Kubernetes or K3s cluster
- Trusted Compute version 1.4.7 or newer
- Linux kernel with:
   - IOMMU enabled
   - VFIO support
   - DRM/i915 driver support

## GPU Driver Management

To enable GPU passthrough, unbind the GPU and bind it to the `vfio-pci` device driver.

#### 1. Find GPU PCI Address and Device ID

Identify your GPU's PCI address and device ID:

```bash
$ lspci -nn | grep VGA
# Example output:
# 0000:00:02.0 VGA compatible controller [0300]: Intel Corporation Raptor Lake-P [Iris Xe Graphics] [8086:a7a0] (rev 04)
```

#### 2. Record GPU Render Device Paths

Before unbinding the GPU, list the available DRI devices and record their major and minor numbers. These details are required later for pod annotations.

```bash
$ ls /dev/dri/
# Example output:
#card0  renderD128

Take note of the device paths `/dev/dri/card0` and `/dev/dri/renderD128`.

#Record Major and Minor Numbers
For each device, record the major and minor numbers. This information is required when specifying device access in your pod specification.

$ ls -l /dev/dri/card0
$ ls -l /dev/dri/renderD128

#Example output:
crw-rw---- 1 root video 226,   0 ... /dev/dri/card0
crw-rw---- 1 root video 226, 128 ... /dev/dri/renderD128

#Here, `226` is the major number and `0` or `128` is the minor number for each device, respectively.
```

#### 3. Unbind Bind to vfio-pci Device driver

Replace the variables with your actual GPU PCI address and device ID if different from the example.

```bash
$ export GPU_PCI="0000:00:02.0"
$ export GPU_DID="8086 a7a0"

# Unbind the GPU from the i915 driver
$ echo "$GPU_PCI" | sudo tee /sys/bus/pci/drivers/i915/unbind

# Load the vfio-pci module
$ sudo modprobe vfio-pci

# Register the GPU device ID with vfio-pci
$ echo "$GPU_DID" | sudo tee /sys/bus/pci/drivers/vfio-pci/new_id

# Bind the GPU to vfio-pci
$ echo "$GPU_PCI" | sudo tee /sys/bus/pci/drivers/vfio-pci/bind
```

#### 4. Verify VFIO Binding

```bash
# After binding, verify that the VFIO device files exist:
$ ls -l /dev/vfio

#You should see at least two entries: a control file (usually `vfio`) and a directory or file with a group number (e.g., `1`). 
# The group number should correspond to the IOMMU group of your GPU.
#If these files are present, the GPU is successfully bound to VFIO and ready for passthrough.

# Verify driver binding
$ lspci -nnk -d 8086:a7a0

# Output should show:
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

## Deploy sample application
The GPU passthrough can be verified by deploying [an OpenCL image](https://github.com/intel/intel-device-plugins-for-kubernetes/tree/v0.34.0/demo/intel-opencl-icd) which runs **clinfo** outputting the GPU capabilities (detected by driver installed to the image).

#### 1. Make the image available to the cluster:
Clone & Build image:
```bash
# Use desired release tag or main
$ git clone https://github.com/intel/intel-device-plugins-for-kubernetes -b v0.34.0 
$ cd intel-device-plugins-for-kubernetes
$ make intel-opencl-icd

#Tag and push the intel-opencl-icd image to a repository available in the cluster.
$ docker tag intel/intel-opencl-icd:devel <repository>/intel/intel-opencl-icd:latest
$ docker push <repository>/intel/intel-opencl-icd:latest
```

#### 2. Preparing NRI Annotations

To enable GPU passthrough with Trusted compute, you must specify device annotations in your pod specification.

**Steps to Prepare NRI Annotation:**

1. **Identify Required Device Files:**
   ```bash
   #List VFIO devices and IOMMU group:
   $ ls /dev/vfio
     #Output will show `vfio` and one or more numbers (e.g., `1`). The number is your IOMMU group (`n`).
   ```
2. **Get Device Major and Minor Numbers:**
   
   ```bash
   #For each device, run:
   $ ls -l /dev/vfio/vfio
   $ ls -l /dev/vfio/<n>      # Replace <n> with your IOMMU group number
   
   #Example output:
   crw-rw-rw- 1 root root 10, 196 ... /dev/vfio/vfio # Major 10, minor 196
   crw------- 1 root root 510,   0 ... /dev/vfio/1 # Major 510, minor 0
   ```

3. **Add Devices to Pod Annotation:**
   
   In your pod spec, under `metadata.annotations`, add each device with its `path`, `type` (`c` for character device), `major`, `minor`, and `file_mode` (e.g., `666` for read/write).
   

4. **Add the following annotations (required):**
  - `default_memory`: Specifies the minimum memory (in MB) allocated to the Kata VM. Our sample application requires at least 4096 MB (4 GB), but you can increase this value based on your application's requirements.
  - `pcie_root_port`: Sets the number of PCIe root ports for device hot-plug support. The GPU will be hot-plugged to the VM on a PCIe root port, so the minimum required value for `pcie_root_port` is 1.
  - `hot_plug_vfio`: Enables hot-plugging of VFIO devices to the specified PCIe root port.

Refer to the sample application pod specification below for a complete example.

## Pod Specification for sample application

Create a pod specification with proper GPU device annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: intel-opencl-icd
  annotations:
    io.katacontainers.config.hypervisor.default_memory: "4096" #minimum default_memory requiedment is 4GB
    io.katacontainers.config.hypervisor.pcie_root_port: "1" #minimum pcie_root_port is 1
    io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port" #gpu is hot_plused to root-port
    devices.noderesource.dev/container.intel-opencl-icd: | #intel-opencl-icd is container name
      - path: /dev/vfio/vfio
        type: c
        major: 10
        minor: 196
        file_mode: 666
      - path: /dev/vfio/1
        type: c
        major: 510
        minor: 0
        file_mode: 666
      - path: /dev/dri/card0
        type: c
        major: 226
        minor: 0
        file_mode: 666
      - path: /dev/dri/renderD128
        type: c
        major: 226
        minor: 128
        file_mode: 666
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  containers:
  - name: intel-opencl-icd
    image: <repository>/intel/intel-opencl-icd:latest #update based on your repository
    imagePullPolicy: Always
    resources: # modify as per your requirement
      requests:
        cpu: 1
        memory: "4Gi"
      limits:
        cpu: 2
        memory: "8Gi"
```

## Pod Deployment and Verification

After deploying the `intel-opencl-icd` pod, verify GPU access by checking the pod logs:

```bash
$ kubectl logs intel-opencl-icd
```

If GPU passthrough is successful, the output should display information about the detected GPU and its capabilities, as reported by the `clinfo` tool inside the container.

If you encounter errors or the GPU is not detected, review the previous steps to ensure that the device files are correctly annotated and the GPU is properly bound to the `vfio-pci` driver.

## Revert GPU Binding

After you are done using GPU passthrough, you may want to revert the GPU binding from `vfio-pci` back to the default GPU driver so the host regains access to the GPU.

To restore the GPU to the host, perform the following steps:

```bash
# 1. Unbind GPU from vfio-pci
echo "$GPU_PCI" | sudo tee /sys/bus/pci/drivers/vfio-pci/unbind

# 2. Remove GPU device ID from vfio-pci
echo "$GPU_DID" | sudo tee /sys/bus/pci/drivers/vfio-pci/remove_id

# 3. Rebind GPU to i915 driver
echo "$GPU_PCI" | sudo tee /sys/bus/pci/drivers/i915/bind

# 4. Verify the GPU is back on i915
lspci -nnk -d $GPU_DID
# Output should show:
# Kernel driver in use: i915

This restores the GPU to its original state for use by the host system.
```