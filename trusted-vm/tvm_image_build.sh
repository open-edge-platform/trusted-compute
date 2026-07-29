#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "INFO: Building Trusted-VM image"

# Build GPU telemetry tools (qmassa, qmmd) in a Rust container
echo "INFO: Building GPU telemetry tools (qmassa, qmmd) in rust:1.88 container"
docker run --rm \
    -e DEBIAN_FRONTEND=noninteractive \
    -v "${SCRIPT_DIR}:/trusted-vm" \
    docker.io/library/rust:1.88 \
    /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh

# Build NPU telemetry tool (npu-reader) using PyInstaller.
# Downloads npu_monitor_tool.py from edge-ai-libraries at a pinned commit and
# bundles it with the TC-specific npu_reader_tc.py into a standalone binary.
echo "INFO: Building npu-reader in python:3.11-slim container (PyInstaller)"
docker run --rm \
    -v "${SCRIPT_DIR}:/trusted-vm" \
    docker.io/library/python:3.11-slim \
    /bin/bash /trusted-vm/npu-telemetry/build_npu_reader.sh



# Build Trusted VM image in Ubuntu container
echo "INFO: Building Trusted-VM image in Ubuntu container"
docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v "${SCRIPT_DIR}":/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
