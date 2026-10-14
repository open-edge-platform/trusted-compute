#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# base:    minimal guest rootfs only
# gpu-npu: base + GPU/NPU telemetry agents and the GPU prestart hook
# custom:  gpu-npu + extra packages from CUSTOM_EXTRA_PKGS (e.g. debugging tools)
IMAGE_VARIANT="${IMAGE_VARIANT:-base}"
case "${IMAGE_VARIANT}" in
    base|gpu-npu|custom) ;;
    *) echo "ERROR: IMAGE_VARIANT must be one of: base, gpu-npu, custom" >&2; exit 1 ;;
esac

echo "INFO: Building Trusted-VM image (variant: ${IMAGE_VARIANT})"

if [[ "${IMAGE_VARIANT}" != "base" ]]; then
    # Build GPU telemetry tools (qmassa, qmmd) in a Rust container
    echo "INFO: Building GPU telemetry tools (qmassa, qmmd) in rust:1.88 container"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "${SCRIPT_DIR}:/trusted-vm" \
        docker.io/library/rust:1.88 \
        /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh

    # Build NPU telemetry tool (npu-reader) using PyInstaller.
    # Downloads npu_reader.py and npu_monitor_tool.py from edge-ai-libraries at a
    # pinned commit, applies TC-specific patches to npu_reader.py, then bundles
    # them into a standalone binary.
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
    -e IMAGE_VARIANT="${IMAGE_VARIANT}" \
    -e CUSTOM_EXTRA_PKGS="${CUSTOM_EXTRA_PKGS:-}" \
    -e SECCOMP="${SECCOMP:-yes}" \
    -v /dev:/dev \
    -v "${SCRIPT_DIR}":/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
