#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Edge Microvisor Toolkit (EMT) guest OS build flow. The rootfs and its kernel
# come from an EMT image config under imageconfigs/, built by the toolkit in
# build-microvisor-image; this script layers the kata agent, hooks and telemetry
# on top and turns the result into a Trusted VM image. Independent of the Debian
# flow in ../debian.

set -euo pipefail

# Root of trusted-vm/, mounted as /trusted-vm inside the build containers.
TVM_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

IMAGE_VARIANT="${IMAGE_VARIANT:-npu}"
case "${IMAGE_VARIANT}" in
    minimal|gpu|npu|custom) ;;
    *) echo "ERROR: IMAGE_VARIANT must be one of: minimal, gpu, npu, custom" >&2; exit 1 ;;
esac

echo "INFO: Building Trusted-VM image (guest OS: emt, variant: ${IMAGE_VARIANT})"

# Resolved here rather than in the build container, which has no yq.
VARIANT_CONFIG="${TVM_ROOT}/os/emt/variants/emt-${IMAGE_VARIANT}-features.json"
[[ -f "${VARIANT_CONFIG}" ]] || { echo "ERROR: no variant config ${VARIANT_CONFIG}" >&2; exit 1; }
IMAGE_FEATURES="$(yq -p=json -o=yaml '.features[]' "${VARIANT_CONFIG}" | tr '\n' ' ')"
has_feature() { [[ " ${IMAGE_FEATURES} " == *" $1 "* ]]; }

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
    -e IMAGE_FEATURES="${IMAGE_FEATURES}" \
    -v /dev:/dev \
    -v "${TVM_ROOT}":/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/os/emt/image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
