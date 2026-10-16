# Trusted Compute

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/open-edge-platform/trusted-compute/badge)](https://scorecard.dev/viewer/?uri=github.com/open-edge-platform/trusted-compute)

## Overview

Trusted Compute is a set of software-defined security extensions that utilize
the hardware security capabilities of a node.

Trusted Compute runs directly on an Ubuntu node in two deployment models:

- **Kubernetes:** K3s or an existing single-node Kubernetes cluster, with host
  attestation and VM-isolated container workloads.
- **Docker/container-based:** Docker Engine and Compose, with VM-isolated
  containers but without the Kubernetes host-attestation services.

Both models use Kata Containers and QEMU/KVM for isolated execution.
See the [architecture and trust model](docs/overview.md) for security boundaries.

## Get Started

1. Check the [platform prerequisites](docs/prerequisites.md).
2. Choose a [deployment model](docs/deployment-options.md).
3. [Download the package](docs/trusted_compute_baremetal.md), then follow the
   [Kubernetes](docs/kubernetes.md) or [Docker](docs/docker.md) workflow.

The [documentation index](docs/README.md) also covers device passthrough,
attestation, troubleshooting and sample applications.

## Develop

The following are development/build prerequisites, not deployment-host
requirements. For deployment, use the
[Ubuntu 24.04 host checklist](docs/prerequisites.md).

- Ubuntu 22.04
- Docker.io
- Docker proxy as mentioned in the Docker documentation
- User should have sudo permission
- Install required packages (e.g., `build-essential` and other GNU build tools)
- Network connection
- At least 256 GB NVMe or SATA storage
- 4–8 GB RAM
- 8-core or better CPU
