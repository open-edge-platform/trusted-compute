#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

echo "INFO: Building Trusted-VM image"

# Build GPU telemetry tools (qmassa, qmmd) in rust:1.88 container
echo "INFO: Building qmassa and qmmd in rust:1.88 container"
docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "${PWD}/trusted-vm:/trusted-vm" \
    docker.io/library/rust:1.88 \
    /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh

# Download jq
echo "INFO: Downloading jq"
mkdir -p ${PWD}/trusted-vm/gpu-telemetry/binaries
jq_version="1.7.1"
jq_sha256="5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5"
curl -fsSL --retry 3 "https://github.com/jqlang/jq/releases/download/jq-${jq_version}/jq-linux-amd64" -o "${PWD}/trusted-vm/gpu-telemetry/binaries/jq"
echo "${jq_sha256}  ${PWD}/trusted-vm/gpu-telemetry/binaries/jq" | sha256sum -c -
chmod +x "${PWD}/trusted-vm/gpu-telemetry/binaries/jq"

# Build Trusted VM image in Ubuntu container
echo "INFO: Building Trusted-VM image in Ubuntu container"
docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v ${PWD}:/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
