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

## Configuration and Capability Comparison

| Area | Kubernetes | Docker |
| --- | --- | --- |
| Platform preparation | K3s helper or an existing single-node containerd cluster | Existing Docker Engine and Compose v2 |
| Installer | `sudo ./install.sh --k3s` or `--k8s` | `sudo ./install.sh --docker` |
| Component management | Helm charts and Kubernetes resources | `docker/tw-docker-deploy.yaml` in the package |
| Application launch | Pod spec or application Helm chart | `docker run` or application Compose file |
| Runtime selection | `runtimeClassName: kata-qemu` | `--runtime io.containerd.kata.v2` |
| VM configuration | Pod annotations and installed QEMU configuration | Container/Compose annotations and installed Kata configuration |
| Host attestation | Included; trust failures can cordon the node | Not installed |
| Device delivery | VFIO plus CDI annotations through NRI | VFIO group devices in the container configuration |
| Networking | Cluster CNI, Services and applicable NetworkPolicies | Docker networks and published ports |
| Logs | `kubectl logs`, events, K3s/containerd journal | `docker logs`, Compose logs, Docker journal |

Use the shared [capabilities guide](capabilities.md) for the VM lifecycle and
security concepts rather than assuming feature parity between the models.

## Continue to Installation

1. Complete the [shared prerequisites](prerequisites.md).
2. [Download and extract the package](trusted_compute_baremetal.md).
3. Follow exactly one workflow:
   [Kubernetes](kubernetes.md) or [Docker](docker.md).
