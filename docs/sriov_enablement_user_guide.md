# SR-IOV Enablement User Guide

Prepare an Intel platform for SR-IOV using the provided automation scripts.

| Script | Purpose |
| --- | --- |
| [`setup_sriov_host.sh`](../baremetal/setup_sriov_host.sh) | Install Intel kernel overlay, configure GRUB, verify SR-IOV |
| [`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) | Create VFs, bind to vfio-pci, generate CDI specs |

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

**Revert GRUB to original state:**

```bash
sudo ./setup_sriov_host.sh revert
sudo reboot
```

---

## 3. Create SR-IOV Virtual Functions

[`setup_sriov_vfs.sh`](../baremetal/setup_sriov_vfs.sh) creates VFs, binds a subset to vfio-pci, and generates CDI device specs under `/etc/cdi/`.

**Create all supported VFs and bind all to vfio-pci:**

```bash
sudo ./setup_sriov_vfs.sh setup
```

**Create M VFs, bind only N to vfio-pci** (N ≤ M):

```bash
TOTAL_VFS=4 BIND_VFS=2 sudo ./setup_sriov_vfs.sh setup
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

