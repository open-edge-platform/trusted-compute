# Deployment Options

[Documentation home](README.md)

Trusted Compute has **two primary deployment models**. Select the model before
downloading and installing the package.

## Kubernetes Deployment

Choose Kubernetes when you need Kubernetes scheduling, Helm-based application
management, host attestation and VM-isolated pods.

- **K3s (`--k3s`):** prepare a standalone node using the supplied K3s helper,
  then install Trusted Compute. K3s manages the component charts through
  `HelmChart` resources.
- **Existing Kubernetes (`--k8s`):** install on an already functioning
  single-node cluster with containerd. The installer does not create this cluster;
  it invokes Helm directly and configures the local runtime.

Both variants use `runtimeClassName: kata-qemu`. They install the same functional
components, but have different containerd configuration paths and chart-management
workflows.

## Docker/Container-Based Deployment

Choose Docker when you need VM-isolated containers on one host without a
Kubernetes control plane. Docker Compose runs the privileged `kata-deploy`
installer container; applications run separately using
`runtime: io.containerd.kata.v2`.

This mode does **not** install the Trust Agent, verifier databases/services,
Attestation Manager, NRI device injector or Kubernetes scheduling enforcement.
The Secure Boot prerequisite still applies. Do not interpret a running Docker
container as a host attestation result.

## Continue to Installation

1. Complete the prerequisites for [Kubernetes](kubernetes.md#prerequisites) or
   [Docker](docker.md#prerequisites).
2. Download the package and install Trusted Compute using exactly one workflow:
   [Kubernetes](kubernetes.md#download-the-installation-package) or
   [Docker](docker.md#download-the-installation-package).
