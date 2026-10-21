#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Debian guest OS build flow

set -euo pipefail

# Mounted as /trusted-vm inside the build containers.
TVM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

IMAGE_VARIANT="${IMAGE_VARIANT:-npu}"
case "${IMAGE_VARIANT}" in
    minimal|gpu|npu|custom) ;;
    *) echo "ERROR: IMAGE_VARIANT must be one of: minimal, gpu, npu, custom" >&2; exit 1 ;;
esac

echo "INFO: Building Trusted-VM image (guest OS: debian, variant: ${IMAGE_VARIANT})"

VARIANT_CONFIG="${TVM_ROOT}/os/debian/variants/debian-${IMAGE_VARIANT}-packages.json"
[[ -f "${VARIANT_CONFIG}" ]] || { echo "ERROR: no variant config ${VARIANT_CONFIG}" >&2; exit 1; }
has_feature() { yq -p=json -o=yaml '.features[]' "${VARIANT_CONFIG}" | grep -qx "$1"; }

if has_feature gpu-telemetry; then
    echo "INFO: Building GPU telemetry tools (qmassa, qmmd) in rust:1.88 container"
    docker run --rm \
        -e DEBIAN_FRONTEND=noninteractive \
        -v "${TVM_ROOT}:/trusted-vm" \
        docker.io/library/rust:1.88 \
        /bin/bash /trusted-vm/build_gpu_telemetry_tools.sh
fi

if has_feature npu-telemetry; then
    echo "INFO: Building npu-reader in python:3.11-slim container (PyInstaller)"
    docker run --rm \
        -v "${TVM_ROOT}:/trusted-vm" \
        docker.io/library/python:3.11-slim \
        /bin/bash /trusted-vm/npu-telemetry/build_npu_reader.sh
fi

echo "INFO: Building Trusted-VM image in Ubuntu container"
docker run --rm \
    --privileged \
    -e IMAGE_VARIANT="${IMAGE_VARIANT}" \
    -e CUSTOM_EXTRA_PKGS="${CUSTOM_EXTRA_PKGS:-}" \
    -e SECCOMP="${SECCOMP:-yes}" \
    -v /dev:/dev \
    -v "${TVM_ROOT}":/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/os/debian/image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
