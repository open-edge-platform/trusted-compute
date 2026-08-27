# SR-IOV Enablement User Guide

Prepare an Intel platform for SR-IOV using the provided automation scripts.

| Script | Purpose |
| --- | --- |
| [`setup_sriov_host.sh`](../baremetal/setup_sriov_host.sh) | Install Intel kernel overlay, configure GRUB, verify SR-IOV |
| [`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) | Create VFs, bind to vfio-pci, generate CDI specs |

---

## Table of Contents

- [1. BIOS Prerequisites](#1-bios-prerequisites)
- [2. Install Kernel and Configure GRUB](#2-install-kernel-and-configure-grub)
- [3. Create SR-IOV Virtual Functions](#3-create-sr-iov-virtual-functions)
- [4. Deploy Sample Application](#4-deploy-sample-application)
  - [Deploy with Kubernetes (K3s/K8s)](#deploy-with-kubernetes-k3sk8s)
  - [Deploy with Docker Compose](#deploy-with-docker-compose)
- [5. Remove VFs and Revert Binding](#5-remove-vfs-and-revert-binding)

---

## 1. BIOS Prerequisites

These are enabled by default; verify they were not inadvertently disabled. Names and menus vary by BIOS.

| Setting | Menu | Value |
| --- | --- | --- |
| Intel Virtualization Technology (VMX) | Advanced → CPU Configuration → VMX | Enable |
| Intel VT for Directed I/O (VT-d) | Advanced → System Agent (SA) Configuration → VT-d | Enable |

---

## 2. Install Kernel and Configure GRUB

[`setup_sriov_host.sh`](../baremetal/setup_sriov_host.sh) automates overlay repo setup, GPG key, apt pin, kernel install, and GRUB configuration.

**Install:**

```bash
sudo ./setup_sriov_host.sh install
```

The script defaults to the `6.18` kernel branch and `MAX_VFS=7`. Override with environment variables:

```bash
KERNEL_BRANCH=6.12 MAX_VFS=4 sudo ./setup_sriov_host.sh install
```

**Reboot after install:**

```bash
sudo reboot
```

**Verify the installation:**

```bash
sudo ./setup_sriov_host.sh verify
```

Expected output includes the running Intel kernel version, a non-zero `sriov_totalvfs`, and the required kernel command-line parameters.

---

## 3. Create SR-IOV Virtual Functions

[`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) creates VFs, binds a subset to vfio-pci, and generates CDI device specs under `/etc/cdi/`.

**Create all supported VFs and bind all to vfio-pci:**

```bash
sudo ./setup_sriov_vfs.sh setup
```

**Create and bind a specific number of VFs to vfio-pci:**

```bash
NUM_VFS=2 sudo ./setup_sriov_vfs.sh setup
```

The bound VFs are exposed as CDI devices:

```
gpu.intel.com/igpu=tc1
gpu.intel.com/igpu=tc2
```

CDI spec files are written to `/etc/cdi/intel-igpu-tc{N}.yaml`.

**Remove all VFs and CDI specs:**

```bash
sudo ./setup_sriov_vfs.sh remove
```

---

## 4. Deploy Sample Application

SR-IOV VF passthrough can be verified by deploying a workload that uses the GPU inside a Kata VM. The example below uses [an OpenCL image](https://github.com/intel/intel-device-plugins-for-kubernetes/tree/v0.36.0/demo/intel-opencl-icd) which runs **clinfo**, outputting the GPU capabilities detected by the driver installed in the image.

> **Note:** Follow either the Kubernetes (K3s/K8s) or Docker Compose deployment section below based on your installation. Each VF can run an independent workload simultaneously — one pod/container per CDI device (`tc1`, `tc2`, …).

### Build and Push the Image

```bash
# Use the desired release tag or main
git clone https://github.com/intel/intel-device-plugins-for-kubernetes -b v0.36.0
cd intel-device-plugins-for-kubernetes
make intel-opencl-icd

# Tag and push to a repository available in the cluster
docker tag intel/intel-opencl-icd:0.36.0 <repository>/intel-opencl-icd:0.36.0
docker push <repository>/intel-opencl-icd:0.36.0
```

### Deploy with Kubernetes (K3s/K8s)

The following steps apply whether Trusted Compute was installed with the K3s or K8s option — both use `kubectl` and the same `kata-qemu` runtime class.

Create a pod specification referencing the VF CDI device. The `cdi-devices.noderesource.dev/container.<name>` annotation injects the VF into the Kata VM:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: intel-opencl-icd-vf1
  annotations:
    io.katacontainers.config.hypervisor.default_memory: "2048"
    io.katacontainers.config.hypervisor.pcie_root_port: "1"
    io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
    io.katacontainers.config.hypervisor.kernel_params: "i915.enable_guc=3"
    cdi-devices.noderesource.dev/container.intel-opencl-icd-vf1: |
      - gpu.intel.com/igpu=tc1
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  containers:
    - name: intel-opencl-icd-vf1
      image: <repository>/intel-opencl-icd:0.36.0
      imagePullPolicy: Always
      resources:  # adjust as per your requirement
        requests:
          cpu: 1
          memory: "2Gi"
        limits:
          cpu: 2
          memory: "4Gi"
```

Save the pod spec above as `opencl-vf1-pod.yaml`, then deploy and verify:

```bash
# Deploy the pod
kubectl apply -f opencl-vf1-pod.yaml

# Verify GPU access
kubectl exec -it intel-opencl-icd-vf1 -- clinfo
```

To run multiple VFs simultaneously, create one pod per VF, changing the pod name, container name, and CDI device reference (`tc1`, `tc2`, …) for each. All pods can be deployed at once:

```bash
kubectl apply -f opencl-vf1-pod.yaml -f opencl-vf2-pod.yaml
```

If GPU passthrough is successful, `clinfo` will display the detected GPU and its OpenCL capabilities.

**Cleanup:** Delete pods when the workload is complete:

```bash
kubectl delete pod intel-opencl-icd-vf1 intel-opencl-icd-vf2
```

### Deploy with Docker Compose

For Docker deployments, pass the VFIO group device corresponding to the VF. Use the VFIO device path printed by `setup_sriov_vfs.sh` (e.g. `/dev/vfio/14` for VF1, `/dev/vfio/15` for VF2):

```yaml
services:
  intel-opencl-icd:
    image: <repository>/intel-opencl-icd:0.36.0
    runtime: io.containerd.kata.v2
    annotations:
      io.katacontainers.config.hypervisor.default_memory: "2048"
      io.katacontainers.config.hypervisor.pcie_root_port: "1"
      io.katacontainers.config.hypervisor.hot_plug_vfio: "root-port"
      io.katacontainers.config.hypervisor.kernel_params: "i915.enable_guc=3"
    devices:
      - /dev/vfio/14:/dev/vfio/14   # Replace with your VF's IOMMU group device
    volumes:
      - /dev:/dev
    deploy:  # adjust as per your requirement
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
docker compose up -d

# Verify GPU access
docker compose exec intel-opencl-icd clinfo
```

If GPU passthrough is successful, `clinfo` will display the detected GPU and its OpenCL capabilities.

**Cleanup:** Stop and remove the container when done:

```bash
docker compose down
```

---

## 5. Remove VFs and Revert Binding

After all pods/containers are stopped, remove the VFs and CDI specs:

```bash
sudo ./setup_sriov_vfs.sh remove
```

This unbinds all VFs from `vfio-pci`, removes the `vfio-pci` module, and deletes all CDI spec files under `/etc/cdi/intel-igpu-tc*.yaml`. The host GPU (PF) remains available via the `i915`/`xe` driver throughout.

**Revert GRUB to original state:**

```bash
sudo ./setup_sriov_host.sh revert
sudo reboot
```

