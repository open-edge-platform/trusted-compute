#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/tcvm_config_lib.sh"

TCVM_CONFIG_FILE="${TCVM_CONFIG_FILE:-${TCVM_USER_CONFIG}}"
tcvm_config_load "${TCVM_CONFIG_FILE}"
tcvm_config_print
# The rootfs is extracted from the existing base image, so it must match this selection
os_check_base_image || tcvm_die "the ${TCVM_OS} base image must be rebuilt; run 'make build-tcvm-image'"
# Resolved copy with build info: read by the build container and installed in the guest
tcvm_config_write "${SCRIPT_DIR}/build/tcvm.config" yes

echo "INFO: Building Trusted-VM image"

if tcvm_enabled gpu-telemetry; then
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
if tcvm_enabled npu-telemetry; then
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
    -e TCVM_CONFIG_FILE=/trusted-vm/build/tcvm.config \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
