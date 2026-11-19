#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Edge Microvisor Toolkit guest OS definition, sourced by scripts/tcvm_config_lib.sh.
# Every os/<name>/<name>_profile.sh must define TCVM_OS_DESCRIPTION, TCVM_OS_FEATURES,
# os_feature_packages, os_image_packages, os_generate_image_config and os_check_base_image.

TCVM_EMT_BASE_CONFIG="${TCVM_ROOT_DIR}/os/emt/trusted-compute-os.json"

# Copy of the image config the EMT tarball was built from, saved by 'make build-microvisor-image'
TCVM_EMT_BUILT_CONFIG="${TCVM_ROOT_DIR}/build/microvisor_src/out/images/trusted-compute-os/trusted-compute-os.json"

TCVM_OS_DESCRIPTION="Edge Microvisor Toolkit (EMT) rootfs and kernel"
TCVM_OS_FEATURES=(gpu gpu-telemetry npu npu-telemetry custom)

# Packages of the built-in features; custom packages come from TCVM_CUSTOM_PACKAGES
os_feature_packages() {
    case "$1" in
        gpu)   echo "kernel-drivers-gpu linux-firmware-i915" ;;
        npu)   echo "intel-npu-driver intel-npu-firmware" ;;
    esac
}

# Packages installed on top of EMT minimal-os-packages: base config plus enabled features.
os_image_packages() {
    command -v yq > /dev/null || tcvm_die "yq is required to read ${TCVM_EMT_BASE_CONFIG}"
    { yq -p json -o yaml '.SystemConfigs[0].packages[]' "${TCVM_EMT_BASE_CONFIG}"; tcvm_packages | tr ' ' '\n'; } \
        | sort -u | xargs
}

# Writes the EMT image config with packages for the enabled features to $1.
os_generate_image_config() {
    PKGS="$(os_image_packages)" yq -I 4 '.SystemConfigs[0].packages = (strenv(PKGS) | split(" "))' "${TCVM_EMT_BASE_CONFIG}" > "$1"
}


os_check_base_image() {
    local current rc=0
    current="$(mktemp)"
    os_generate_image_config "${current}"
    if ! cmp -s "${current}" "${TCVM_EMT_BUILT_CONFIG}"; then
        tcvm_warn "the EMT image is missing or was built for a different selection"
        rc=2
    fi
    rm -f "${current}"
    return "${rc}"
}
