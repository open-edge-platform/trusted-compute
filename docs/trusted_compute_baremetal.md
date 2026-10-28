# Trusted Compute Installation Package

[Documentation home](README.md) | [Deployment options](deployment-options.md)

This page describes the package layout and compatibility notes. Prerequisites,
package download, installation and workload launch instructions are included in
the [Kubernetes](kubernetes.md) and [Docker](docker.md) guides.

## Download a Release

Follow the download and extraction steps for your deployment model:

- [Kubernetes package download](kubernetes.md#download-the-installation-package)
- [Docker package download](docker.md#download-the-installation-package)

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
