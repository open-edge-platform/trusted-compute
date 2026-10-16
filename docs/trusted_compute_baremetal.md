# Trusted Compute Installation Package

[Documentation home](README.md) | [Deployment options](deployment-options.md)

This page is the common package-download entry point. Installation and workload
launch instructions are now separated into the [Kubernetes](kubernetes.md) and
[Docker](docker.md) guides. Complete the [shared prerequisites](prerequisites.md)
first.

## Download a Release

Install [ORAS](https://oras.land/docs/installation), choose a published release,
and download it into an empty working directory:

```bash
VERSION=1.5.3
oras pull "registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package:${VERSION}"
tar -xvf trusted-compute-installation-package.tgz
cd trusted-compute-installation-package
```

`1.5.3` is an example release, not a floating "latest" tag. To list available
versions before choosing:

```bash
oras repo tags registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package
```

Keep the extracted directory for configuration and uninstallation. Use the
installer from the release package, not a copied standalone script from the
repository: package creation fills in component versions and includes the
artifacts the installer needs.

## Package Layout

| Path | Purpose |
| --- | --- |
| `install.sh`, `uninstall.sh` | Mode-specific installation and removal |
| `k3s/k3s.sh` | Optional K3s installation/removal helper |
| `charts/`, `images/` | Packaged component charts and image archives |
| `manifests/trusted-compute.yaml` | K3s namespaces and HelmChart configuration |
| `containerd/config-v3.toml.tmpl` | containerd v3 template for Kata and NRI |
| `docker/tw-docker-deploy.yaml` | Docker Compose runtime installer |
| `tools/intel-igpu-vfio-bind.sh` | Whole-iGPU passthrough helper |
| `tools/intel-npu-vfio-bind.sh` | NPU passthrough helper |
| `docs/` | Deployment and capability documentation |

The SR-IOV helper is currently used from a repository checkout, not from the
release package's `tools/` directory. See the
[SR-IOV guide](sriov_enablement_user_guide.md).

## Install One Deployment Model

- [Kubernetes installation](kubernetes.md#installation): select the K3s or existing
  Kubernetes variant.
- [Docker installation](docker.md#installation): install the Kata runtime through
  Compose, then launch containers separately.

Running `sudo ./install.sh` without a mode opens an interactive selector.
Explicit mode flags are preferable for repeatable instructions. Installation
modes are mutually exclusive on a node.

For older packages, Trusted Compute 1.5.0 through 1.5.2 require Docker 29.4.x
(tested with 29.4.3) rather than 29.5 or later. The documented restriction is
removed in Trusted Compute 1.5.3 and later; this is not a guarantee of compatibility
with all future Docker releases.
