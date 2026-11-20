# Build Trusted Compute from Source

[Documentation home](README.md) | [Installation package](trusted_compute_baremetal.md)

This guide explains how to build a custom Trusted VM and a custom installation
package from it, in two steps:

1. [Build Custom Trusted VM](#1-build-custom-trusted-vm)
2. [Build Custom Installation Package](#2-build-custom-installation-package)

To deploy a released package instead, follow the [Kubernetes](kubernetes.md)
or [Docker](docker.md) guide.

## Build Host Prerequisites

These requirements apply to the build machine, not to the deployment host.

| Requirement | Notes |
| --- | --- |
| OS | Ubuntu 22.04 or later, x86-64 |
| CPU and memory | 8 or more cores; 4–8 GB RAM minimum, more speeds up the Trusted VM build |
| Storage | At least 256 GB free NVMe or SATA storage |
| Access | `sudo` permission; most targets prompt for the password once |
| Network | Access to GitHub, GitHub Container Registry and Docker Hub. Configure proxies for the shell **and** for the Docker daemon if needed |

Install these tools:

| Tool | Used by |
| --- | --- |
| `git`, `make`, `build-essential`, `curl`, `tar` | All steps |
| Docker Engine (`docker.io` or Docker CE) | All steps |
| [`yq` v4](https://github.com/mikefarah/yq) (Mike Farah) | All steps. `trusted-vm` refuses to start without it |
| `whiptail` or `dialog` | `make menuconfig` only |
| Go 1.21 or later | Local Attestation Manager image only |
| Helm v3 | Installation package |
| containerd `ctr` | Installation package |

The Trusted VM build also runs the Edge Microvisor Toolkit (EMT) image build
on the host. Check the prerequisites in the
[Edge Microvisor Toolkit repository](https://github.com/open-edge-platform/edge-microvisor-toolkit)
if that step fails because of a missing host tool.

## Get the Source

```bash
git clone https://github.com/open-edge-platform/trusted-compute.git
cd trusted-compute
```

## 1. Build Custom Trusted VM

The Trusted VM is the guest OS that runs every Kata workload. It is built from
the Edge Microvisor Toolkit with the Trusted Compute guest components added.
By default it includes every optional feature except custom packages:

| Option | Default | Adds |
| --- | --- | --- |
| `TCVM_GPU` | `y` | GPU drivers, i915 firmware and the GPU discovery OCI hook |
| `TCVM_GPU_TELEMETRY` | `y` | GPU telemetry tools; needs `TCVM_GPU=y` |
| `TCVM_NPU` | `y` | Intel NPU driver and firmware |
| `TCVM_NPU_TELEMETRY` | `y` | NPU telemetry tool; needs `TCVM_NPU=y` |
| `TCVM_CUSTOM` | `n` | The packages listed in `TCVM_CUSTOM_PACKAGES` |
| `TCVM_CUSTOM_PACKAGES` | `bc gawk igt-gpu-tools pciutils` | Space-separated package names, used when `TCVM_CUSTOM=y` |

Select the features in an interactive menu and build:

```bash
make -C trusted-vm menuconfig
make -C trusted-vm build
```

<img src="images/tcvm-menuconfig.png" alt="Trusted VM feature selection menu" width="800">

Or start from the defaults and edit the file by hand:

```bash
make -C trusted-vm defconfig
# edit trusted-vm/.tcvm.config, for example set TCVM_NPU=n and TCVM_NPU_TELEMETRY=n
make -C trusted-vm build
```

After a successful build, `trusted-vm/build/` contains:

| File | Purpose |
| --- | --- |
| `vmlinuz-<kernel version>` | Trusted VM guest kernel |
| `config-<kernel version>` | Kernel configuration |
| `trusted-vm.img` | Trusted VM guest image |

The kernel file names must match `kernel.name` and `kernel.config` in
[`trusted-workload/kata-deploy/version.yaml`](../trusted-workload/kata-deploy/version.yaml).
Update `version.yaml` when you move to an EMT release with a different kernel.

## 2. Build Custom Installation Package

```bash
make -C baremetal build-local
```

This builds the kata-deploy image from the Trusted VM in `trusted-vm/build/`,
the Attestation Verifier and Attestation Manager images, and then the package
from those local images. The build stops with `Local image not found` if any
image is missing.

The package is written to `baremetal/out/trusted-compute-installation-package.tgz`.

## Clean Up

Run `make -C trusted-vm clean` to remove the Trusted VM sources, rootfs and `trusted-vm/build/`.
