#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/tvm_config_lib.sh"

TVM_CONFIG_FILE="${TVM_CONFIG_FILE:-${TVM_USER_CONFIG}}"
tvm_config_load "${TVM_CONFIG_FILE}"
tvm_config_print
# The Ubuntu build container reads this resolved copy
tvm_config_write "${SCRIPT_DIR}/build/tvm.config"
# Generated on the host (needs yq), installed into the guest by tvm_image_inside_container.sh
tvm_manifest_write "${SCRIPT_DIR}/build/trusted-vm-features.conf"

echo "INFO: Building Trusted-VM image"

if tvm_enabled gpu-telemetry; then
    echo "INFO: Building GPU telemetry tools (qmassa, qmmd) in rust:1.88 container"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "${SCRIPT_DIR}:/trusted-vm" \
        docker.io/library/rust:1.88 \
        /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh
fi

# Build NPU telemetry tool (npu-reader) using PyInstaller.
# Downloads npu_reader.py and npu_monitor_tool.py from edge-ai-libraries at a
# pinned commit, applies TC-specific patches to npu_reader.py, then bundles
# them into a standalone binary.
if tvm_enabled npu-telemetry; then
    echo "INFO: Building npu-reader in python:3.11-slim container (PyInstaller)"
    docker run --rm \
        -v "${SCRIPT_DIR}:/trusted-vm" \
        docker.io/library/python:3.11-slim \
        /bin/bash /trusted-vm/npu-telemetry/build_npu_reader.sh
fi

# Build Trusted VM image in Ubuntu container
echo "INFO: Building Trusted-VM image in Ubuntu container"
docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v "${SCRIPT_DIR}":/trusted-vm \
    -e TVM_CONFIG_FILE=/trusted-vm/build/tvm.config \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
