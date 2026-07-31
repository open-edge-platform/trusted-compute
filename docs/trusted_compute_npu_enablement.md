# NPU Enablement in Trusted Compute Environment

This document provides a step-by-step guide to enable NPU (Neural Processing Unit) passthrough in a Trusted Compute environment. It includes instructions for NPU driver management and running a sample application.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Install Trusted Compute Package](#install-trusted-compute-package)
- [NPU Driver Management](#npu-driver-management)
  - [Bind NPU to vfio-pci](#bind-npu-to-vfio-pci)
  - [Verify VFIO Binding](#verify-vfio-binding)
- [Deploy Sample Application](#deploy-sample-application)
  - [Deploy with K3s](#deploy-with-k3s)
  - [Deploy with Docker Compose](#deploy-with-docker-compose)
- [Revert NPU Binding](#revert-npu-binding)

## Overview

NPU passthrough allows a virtual machine to directly access a physical Intel NPU (also referred to as the VPU / AI Boost accelerator), bypassing the host operating system's drivers. By leveraging VFIO (Virtual Function I/O), the NPU is securely assigned to the VM, enabling AI inference workloads inside the Trusted Compute environment to utilize the NPU with minimal overhead and near-native performance. This is essential for power-efficient, compute-intensive AI/ML inference in a trusted and isolated environment.

## Prerequisites

- Intel CPU with VT-x/VT-d support and an integrated NPU
- IOMMU enabled in BIOS/UEFI and Linux kernel with VFIO and `intel_vpu` driver support
- Kubernetes, K3s, or Docker with Trusted Compute version 1.5.3 or newer

## Install Trusted Compute Package

Follow the [Trusted Compute Installation on Standalone Ubuntu Edge Node](https://github.com/open-edge-platform/trusted-compute/blob/main/docs/trusted_compute_baremetal.md) guide for instructions on installing Trusted Compute on a standalone system.

> **Note:** During the Trusted Compute installation, you will set up either K3s or Docker. Follow the corresponding deployment section in this guide based on which option you chose during installation.

## NPU Driver Management

To enable NPU passthrough, use the `intel-npu-vfio-bind.sh` script located in the `tools/` directory of the Trusted Compute installation package used in the previous step. The script automatically detects the Intel NPU, binds it to the `vfio-pci` driver, and generates a CDI spec at `/etc/cdi/intel-npu-tc-cdi.yaml`.

### Bind NPU to vfio-pci

```bash
sudo ./tools/intel-npu-vfio-bind.sh bind
```

The script auto-detects the Intel NPU and the companion Signal Processing Controller (`8086:b07d`, required for NPU telemetry inside the VM), unbinds both from their native drivers, binds them to `vfio-pci`, prints the assigned VFIO device paths, and generates a CDI spec at `/etc/cdi/intel-npu-tc-cdi.yaml`.

### Verify VFIO Binding

```bash
$ ls /dev/vfio
# Expected: vfio  <n>  <m>  (control file + IOMMU group for NPU + IOMMU group for SPC)

$ lspci -nnk | grep -A3 -iE 'Processing accelerators.*Intel'
# Kernel driver in use: vfio-pci

$ lspci -nnk | grep -A3 -iE 'Signal processing controller'
# Kernel driver in use: vfio-pci
```

## Deploy Sample Application

NPU passthrough can be verified by deploying an open-source [OpenVINO™ Toolkit](https://github.com/openvinotoolkit/openvino) runtime container, which can enumerate the available inference devices (including the NPU) and run inference benchmarks against it.

The check below runs OpenVINO's device query, which lists all detected inference devices. When passthrough is successful, `NPU` appears in the list of available devices.

> **Note:** Follow either the K3s or Docker Compose deployment section below based on your installation.

### Deploy with K3s

Create a pod specification with proper NPU device annotations:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: openvino-npu
  annotations:
    # Required for NPU passthrough
    io.katacontainers.config.hypervisor.default_memory: "4096"
    io.katacontainers.config.hypervisor.pcie_root_port: "1"
    io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
    cdi-devices.noderesource.dev/container.openvino-npu: |
      - npu.intel.com/npu=tc
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  containers:
    - name: openvino-npu
      image: openvino/ubuntu24_runtime:2025.0.0
      imagePullPolicy: Always
      command: ["python3", "-c", "from openvino import Core; print('Available devices:', Core().available_devices)"]
      resources: # modify as per your requirement
        requests:
          cpu: 1
          memory: "2Gi"
        limits:
          cpu: 2
          memory: "4Gi"
```

Save the pod spec above as `openvino-npu-pod.yaml`, then deploy and verify:

```bash
# Deploy the pod
$ kubectl apply -f openvino-npu-pod.yaml

# Verify NPU access
$ kubectl logs openvino-npu
# Expected output includes 'NPU' in the device list, e.g.:
# Available devices: ['CPU', 'NPU']
```

If NPU passthrough is successful, the device list will include `NPU`. If the NPU is not detected, review the previous steps to ensure the NPU is bound to `vfio-pci` and the CDI annotation is correct.

### Deploy with Docker Compose

For Docker deployments, create a `docker-compose.yml` file:

```yaml
services:
  openvino-npu:
    image: openvino/ubuntu24_runtime:2025.0.0
    runtime: io.containerd.kata.v2
    command: ["python3", "-c", "from openvino import Core; print('Available devices:', Core().available_devices)"]
    # Required for NPU passthrough
    annotations:
      io.katacontainers.config.hypervisor.default_memory: "4096"
      io.katacontainers.config.hypervisor.pcie_root_port: "1"
      io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
    devices:
      - /dev/vfio/<n>:/dev/vfio/<n>  # NPU IOMMU group number (from 'VFIO device (NPU)' output)
      - /dev/vfio/<m>:/dev/vfio/<m>  # SPC IOMMU group number (from 'VFIO device (SPC)' output)
    volumes:
      - /dev:/dev
    deploy: #update as per your requirement
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

Deploy and verify:

```bash
# Start the container
$ docker compose up -d

# Verify NPU access
$ docker compose logs openvino-npu
# Expected output includes 'NPU' in the device list, e.g.:
# Available devices: ['CPU', 'NPU']
```

If NPU passthrough is successful, the device list will include `NPU`.

## Revert NPU Binding

After you are done using NPU passthrough, use the same script to restore the NPU to its native driver so the host regains NPU access.

```bash
sudo ./tools/intel-npu-vfio-bind.sh unbind
```

The script unbinds both the NPU and the SPC from `vfio-pci`, rebinds them to their native drivers, and restores both devices to their original state for use by the host system.

```bash
# Verify the NPU is restored to the native driver:
lspci -nnk | grep -A3 -iE 'Processing accelerators.*Intel'
# Output should show:
# Kernel driver in use: intel_vpu
```

## NPU Telemetry

The Trusted Compute environment supports NPU telemetry collection from workloads running in Kata VMs. To enable telemetry, configure the collection endpoint via Kata kernel parameters in your pod/container annotations:

```yaml
# In pod annotations (K3s):
io.katacontainers.config.hypervisor.kernel_params: "push_host=<collector-ip> push_port=<port> push_path=<path>"

# Example for a Prometheus/InfluxDB compatible collector:
io.katacontainers.config.hypervisor.kernel_params: "push_host=192.168.1.100 push_port=8086 push_path=/api/v1/write"
```

Metrics are emitted in InfluxDB line protocol format. If no collector is configured, telemetry collection is silently disabled.
