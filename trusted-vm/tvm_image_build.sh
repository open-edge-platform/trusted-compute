#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "INFO: Building Trusted-VM image"

# Build GPU telemetry tools (qmassa, qmmd) in rust:1.88 container
echo "INFO: Building qmassa and qmmd in rust:1.88 container"
docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "${SCRIPT_DIR}:/trusted-vm" \
    docker.io/library/rust:1.88 \
    /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh



# Build Trusted VM image in Ubuntu container
echo "INFO: Building Trusted-VM image in Ubuntu container"
docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v "${SCRIPT_DIR}":/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
