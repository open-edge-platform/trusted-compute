# SR-IOV Enablement User Guide

Prepare an Intel platform for SR-IOV using the provided automation scripts.

| Script | Purpose |
| --- | --- |
| [`setup_host.sh`](https://github.com/intel/kvm-multios/blob/v0.21.0/host_setup/ubuntu/setup_host.sh) (kvm-multios) | Official Intel host setup: BIOS checks, SR-IOV kernel command-line parameters, GRUB configuration |
| [`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) | Create VFs, bind to vfio-pci, generate CDI specs |

---

## Table of Contents

- [1. BIOS Prerequisites](#1-bios-prerequisites)
- [2. Set Up Host with kvm-multios](#2-set-up-host-with-kvm-multios)
- [3. Create SR-IOV Virtual Functions](#3-create-sr-iov-virtual-functions)
- [4. Deploy Sample Application](#4-deploy-sample-application)
  - [Deploy with Kubernetes (K3s/K8s)](#deploy-with-kubernetes-k3sk8s)
  - [Deploy with Docker Compose](#deploy-with-docker-compose)
- [5. Remove VFs and Revert Binding](#5-remove-vfs-and-revert-binding)
- [6. Revert kvm-multios Host Setup](#6-revert-kvm-multios-host-setup)
- [7. Manual Steps to Set Up Userspace and Kernel](#7-manual-steps-to-set-up-userspace-and-kernel)

---

## 1. BIOS Prerequisites

Check the following settings in BIOS and ensure they match the table below. Names and menus vary by BIOS.

| Setting | Menu | Value |
| --- | --- | --- |
| Intel® Virtualization Technology (Intel® VMX) | Intel Advanced Menu → CPU Configuration → VMX | Enable |
| Intel® Virtualization Technology for Directed I/O (Intel® VT-d) | Intel Advanced Menu → System Agent (SA) Configuration → VT-d | Enable |
| Intel® Volume Management Device (Intel® VMD) controller | Intel Advanced Menu → VMD setup menu → Enable VMD controller | Disable |

---

## 2. Set Up Host with kvm-multios

Use Intel's official [kvm-multios](https://github.com/intel/kvm-multios) host setup script (`v0.21.0`) to configure the host for SR-IOV — this checks BIOS prerequisites, sets the required kernel command-line parameters, and updates GRUB.

> **Note:** Run this from the host's physical/local display session (logged in at the graphical console), not over SSH. `-u GUI` mode configures the desktop session (idle/lock settings, display env) for the logged-in user and requires an active local display.

```bash
cd ~
git clone -b v0.21.0 https://github.com/intel/kvm-multios.git
cd kvm-multios
./host_setup/ubuntu/setup_host.sh -u GUI
```

Use `-u GUI` if the host has a graphical desktop session, or `-u headless` otherwise. The script validates VT-x/VMX and VT-d are enabled and VMD is disabled, then sets `intel_iommu=on,sm_on`, `i915`/`xe` `force_probe`, `enable_guc`, and `max_vfs` kernel parameters before running `update-grub`.

**Reboot after the script completes:**

```bash
sudo reboot
```

**Verify:**

```bash
uname -r
cat /sys/class/drm/card0/device/sriov_totalvfs
cat /proc/cmdline
```

Expected output includes a non-zero `sriov_totalvfs` and the SR-IOV kernel command-line parameters (`intel_iommu=on,sm_on`, `i915.max_vfs=<N>` or `xe.max_vfs=<N>`, etc.) set by the script.

---

## 3. Create SR-IOV Virtual Functions

[`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) creates VFs, binds all of them to vfio-pci, and generates CDI device specs under `/etc/cdi/`.

```bash
cd baremetal
```

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
sudo baremetal/setup_sriov_vfs.sh remove
```

This unbinds all VFs from `vfio-pci`, removes the `vfio-pci` module, and deletes all CDI spec files under `/etc/cdi/intel-igpu-tc*.yaml`. The host GPU (PF) remains available via the `i915`/`xe` driver throughout.

---

## 6. Revert kvm-multios Host Setup

Manually undo the changes `setup_host.sh` made across GRUB, auto-upgrade, desktop/audio, libvirt, swap, and power-management config:

```bash
# GRUB: remove SR-IOV/hibernate kernel params from /etc/default/grub, then:
#   intel_iommu=on,sm_on  i915.max_vfs=<N>/xe.max_vfs=<N>  i915.enable_guc=<N>/xe.enable_guc=<N>
#   i915.force_probe=*/xe.force_probe=*  udmabuf.list_limit=8192  modprobe.blacklist=<i915|xe>
#   resume=UUID=<uuid>  resume_offset=<n>
sudo update-grub

# Re-enable automatic OS updates
sudo systemctl unmask unattended-upgrades.service
sudo systemctl enable --now unattended-upgrades.service
sudo sed -i 's/"0";/"1";/g' /etc/apt/apt.conf.d/20auto-upgrades

# Desktop/display: re-enable Wayland, drop printk/mesa overrides, restore screen blank/lock
sudo sed -i 's/^WaylandEnable=false/#WaylandEnable=false/' /etc/gdm3/custom.conf
sudo rm -f /etc/sysctl.d/99-kernel-printk.conf /etc/profile.d/mesa_driver.sh
sudo sed -i '/source \/etc\/profile\.d\/mesa_driver\.sh/d' /etc/bash.bashrc
gsettings set org.gnome.desktop.session idle-delay 300
gsettings set org.gnome.desktop.screensaver ubuntu-lock-on-suspend 'true'

# Audio: remove anonymous socket forwarding (PulseAudio and/or PipeWire)
sed -i '/auth-anonymous=1 socket=\/tmp\/pulseaudio-socket/d' ~/.config/pulse/default.pa
sed -i '/default-server = unix:\/tmp\/pulseaudio-socket/d' ~/.config/pulse/client.conf
sed -i '/"unix:\/tmp\/pulseaudio-socket"/d' ~/.config/pipewire/pipewire-pulse.conf

# libvirt: revert qemu.conf, sysctl, hooks, sudoers, group membership
sudo sed -i \
  -e 's/^security_default_confined = 0/#security_default_confined = 1/' \
  -e 's/^user = "root"/#user = "libvirt-qemu"/' \
  -e 's/^group = "root"/#group = "kvm"/' \
  /etc/libvirt/qemu.conf   # also remove the added cgroup_device_acl block manually
sudo sed -i \
  -e '/^net.bridge.bridge-nf-call-iptables=0/d' \
  -e '/^net.ipv4.conf.all.route_localnet=1/d' \
  -e 's/^net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' \
  /etc/sysctl.conf
sudo sysctl -p
sudo rm -f /etc/libvirt/hooks/qemu /etc/sudoers.d/multios-sudo
sudo rm -rf /etc/libvirt/hooks/qemu.d
sudo gpasswd -d "$USER" libvirt
sudo systemctl restart libvirtd

# Swap file added for hibernate support
sudo swapoff /swap.img 2>/dev/null || sudo swapoff /swapfile 2>/dev/null
sudo rm -f /swap.img /swapfile /etc/initramfs-tools/conf.d/resume
sudo sed -i '/\/swap\.img\|\/swapfile/d' /etc/fstab
sudo update-initramfs -u -k all

# Power management sleep/hibernate hooks
sudo systemctl disable libvirt-guests-suspend.service libvirt-guests-hibernate.service
sudo rm -f /etc/systemd/system/libvirt-guests-{suspend,hibernate}.service
sudo rm -f /usr/local/bin/libvirt-guests-sleep.sh /usr/local/bin/libvirt-guests-sleep-dep.sh
sudo systemctl daemon-reload

# OpenVINO (optional, only if you no longer need it)
sudo apt-get remove -y openvino* 2>/dev/null
```

**Reboot to apply all reverted changes:**

```bash
sudo reboot
```

---

## 7. Manual Steps to Set Up Userspace and Kernel

> **Alternative to Section 2:** Use this instead of kvm-multios if you prefer to install the Intel kernel overlay and configure GRUB manually.

```bash
# Install prerequisite packages
sudo apt update && sudo apt upgrade
sudo apt install ethtool libbpf1 wayland-protocols -y

# Add the 01.org Intel overlay PPA (noble), GPG key, and apt pin priority
echo "deb https://download.01.org/intel-linux-overlay/ubuntu noble main non-free multimedia kernels
deb-src https://download.01.org/intel-linux-overlay/ubuntu noble main non-free multimedia kernels" | sudo tee /etc/apt/sources.list.d/intel-ptl.list
sudo wget https://download.01.org/intel-linux-overlay/ubuntu/E6FA98203588250569758E97D176E3162086EE4C.gpg -O /etc/apt/trusted.gpg.d/ptl.gpg
echo "Package: *
Pin: release o=intel-iot-linux-overlay-noble
Pin-Priority: 2000" | sudo tee /etc/apt/preferences.d/intel-ptl

# Install the kernel
sudo apt update
sudo apt install -y linux-image-6.18-intel linux-headers-6.18-intel
```

Update `/etc/default/grub`:

```bash
# Required for GuC firmware/SR-IOV
sudo sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT="quiet splash xe.max_vfs=7 xe.force_probe=* modprobe.blacklist=i915 udmabuf.list_limit=8192"/' /etc/default/grub

# Optional: boot a non-default kernel (skip if the installed kernel is already the highest version)
submenu=$(sudo grep -oP "submenu '\K[^']+" /boot/grub/grub.cfg | head -1)
entry=$(sudo grep -oP "menuentry '\K[^']+" /boot/grub/grub.cfg | grep 6.18 | grep -v recovery | head -1)
sudo sed -i "s|^GRUB_DEFAULT=.*|GRUB_DEFAULT=\"${submenu}>${entry}\"|" /etc/default/grub

# Optional: show the GRUB menu at boot
sudo sed -i -e 's/^GRUB_TIMEOUT_STYLE=hidden/#GRUB_TIMEOUT_STYLE=hidden/' -e 's/^GRUB_TIMEOUT=.*/GRUB_TIMEOUT=5/' /etc/default/grub
```

```bash
sudo update-grub
sudo reboot

# Verify the active kernel
uname -a
```

