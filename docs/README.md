# Trusted Compute Documentation

Trusted Compute combines hardware-backed host integrity monitoring with
Kata Containers-based workload isolation. It runs directly on an Ubuntu node.
Choose one of two deployment models:

- **Kubernetes:** use K3s or an existing single-node Kubernetes cluster for
  Helm-managed components, host attestation, and VM-isolated pods.
- **Docker/container-based:** use Docker Engine and Compose for VM-isolated
  containers without a Kubernetes cluster. This installer does **not** deploy
  the host attestation services.

K3s and existing Kubernetes are installation variants of the same deployment
model, not separate security architectures.

## Start Here

1. Read the [overview and trust model](overview.md).
2. Compare [deployment options](deployment-options.md).
3. Complete the prerequisites for [Kubernetes](kubernetes.md#prerequisites) or
   [Docker](docker.md#prerequisites).
4. Follow the [Kubernetes](kubernetes.md#download-the-installation-package) or
   [Docker](docker.md#download-the-installation-package) guide to download the
   installation package and install Trusted Compute.
5. Launch the basic workload in that guide before adding devices or AI workloads.

## Documentation Map

| Area | Guides |
| --- | --- |
| Architecture | [Components, host/VM boundary, security properties](overview.md) |
| Deployment | [Deployment options](deployment-options.md) |
| Installation package | [Package layout and compatibility](trusted_compute_baremetal.md) |
| Kubernetes | [Prerequisites, installation, configuration, launch and removal](kubernetes.md) |
| Docker | [Prerequisites, installation, configuration, launch and removal](docker.md) |
| Common capabilities | [VM lifecycle, integrity, attestation and PCIe passthrough](capabilities.md) |
| Devices | [GPU](trusted_compute_gpu_enablement.md), [NPU](trusted_compute_npu_enablement.md), [GPU SR-IOV](sriov_enablement_user_guide.md) |
| Operations | [Logging, troubleshooting and known limitations](troubleshooting.md) |
| Sample workloads | TBD |

The device guides share host preparation steps, then provide separate Kubernetes
and Docker launch examples. Run only the section for your installed model.
