# Trusted Compute

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/open-edge-platform/trusted-compute/badge)](https://scorecard.dev/viewer/?uri=github.com/open-edge-platform/trusted-compute)

## Overview

Trusted Compute is a set of software-defined security extensions that utilize
the hardware security capabilities of a node.

A user can deploy the Trusted Compute standalone package on a node to achieve
higher security assurances for their workloads.
These extensions enhance node protection through:

- **Continuous Monitoring**
- **Workload Protection through Isolated Execution**

## Get Started

See the [Trusted Compute documentation](docs/README.md) for the architecture
overview and installation guides.

## Develop

To develop Trusted Compute, the following development prerequisites
are required:

- Ubuntu 22.04
- Docker.io
- Docker proxy as mentioned in the Docker documentation
- User should have sudo permission
- Install required packages (e.g., `build-essential` and other GNU build tools)
- Network connection
- At least 256 GB NVMe or SATA storage
- 4–8 GB RAM
- 8-core or better CPU
