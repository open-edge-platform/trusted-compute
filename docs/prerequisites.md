# Shared Platform Prerequisites

[Documentation home](README.md) | [Next: deployment options](deployment-options.md)

Complete this checklist before either installation. The installer checks some
requirements, including Secure Boot, but does not provision the entire security
baseline or certify hardware compatibility.

## Hardware, Firmware and BIOS

| Requirement | Purpose and action |
| --- | --- |
| Intel x86-64 CPU with VT-x/VMX | Enable virtualization in BIOS/UEFI for QEMU/KVM |
| UEFI Secure Boot | Enable it and use trusted, signed boot components; both installation modes check it |
| TPM 2.0 | Required for Kubernetes host attestation; enable it in firmware and expose it to the host |
| VT-d/IOMMU | Required for PCIe passthrough; enable in firmware and the Linux kernel |
| Storage and memory | Budget for host services, downloaded/extracted artifacts, container images, logs and each VM |
| Supported accelerator | Check GPU/NPU model, firmware, guest drivers and IOMMU groups before assigning it |

Install supported firmware updates and establish a known-good baseline before
enrollment. Record firmware and kernel versions for troubleshooting.
There is no single validated memory/storage minimum for every workload in this
repository. Kubernetes additionally runs verifier databases; container limits
must leave room for VM and host-service overhead.

## Host Operating System and Kernel

- Install Ubuntu 24.04 on the host.
- Enable full disk encryption as part of the deployment's security baseline.
  The installer neither enables encryption nor verifies coverage.
- Use a kernel with KVM and vhost/vsock support. For passthrough, also require
  IOMMU and VFIO support.
- Kubernetes attestation needs TPM access and the host measurement interfaces
  used by the Trust Agent, including IMA/securityfs for runtime measurements.
  Coverage depends on the active measurement policy.
- Preserve Secure Boot when changing kernels or installing device drivers.
  Disabling it to load an unsigned driver is not a supported workaround.

Read-only checks on the host:

```bash
uname -m
uname -r
cat /etc/os-release
lscpu | grep -E 'Architecture|Virtualization'
mokutil --sb-state
ls -l /dev/kvm
```

Expect `x86_64`, Ubuntu 24.04, virtualization support, `SecureBoot enabled`, and an
accessible KVM device. For Kubernetes attestation, also check:

```bash
ls -l /dev/tpm*
sudo ls /sys/kernel/security
```

For device passthrough, inspect IOMMU availability before binding devices:

```bash
sudo dmesg | grep -Ei 'DMAR|IOMMU'
find /sys/kernel/iommu_groups -type l
lspci -nnk
```

An empty IOMMU group listing is a reason to fix host configuration, not to bypass
isolation checks. Device-specific kernel requirements are in the
[GPU](trusted_compute_gpu_enablement.md), [NPU](trusted_compute_npu_enablement.md)
and [SR-IOV](sriov_enablement_user_guide.md) guides.

## Software, Access and Networking

- Root/sudo access for installation and host device changes.
- `mokutil` for the installer's Secure Boot check.
- [ORAS](https://oras.land/docs/installation) to download the release package,
  plus `tar` to extract it.
- Working DNS, time synchronization and registry/network access. Packaged
  images do not guarantee a fully air-gapped deployment: workload images,
  chart dependencies and initial platform installation can need network access.
- Configure proxies and registry credentials for the chosen runtime, not only
  for the interactive shell. Keep cluster/service networks in proxy exclusions.
- A maintenance window: installation updates host runtime files and can restart
  K3s or containerd. Back up existing configuration and workload data.

Only one Trusted Compute installation mode may own a node at a time.
Uninstall the existing Trusted Compute mode before switching between `--k3s`,
`--k8s` and `--docker`. This restriction concerns Trusted Compute installations,
not the mere presence of Docker as an image-build tool.

Continue with the mode-specific [Kubernetes prerequisites](kubernetes.md#prerequisites)
or [Docker prerequisites](docker.md#prerequisites).
