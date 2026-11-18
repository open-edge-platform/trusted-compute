#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Edge Microvisor Toolkit guest OS definition, sourced by scripts/tvm_config_lib.sh.
# Every os/<name>/<name>_profile.sh must define TVM_OS_DESCRIPTION, TVM_OS_FEATURES,
# os_feature_packages, os_image_packages, os_generate_image_config and os_check_base_image.

TVM_EMT_BASE_CONFIG="${TVM_ROOT_DIR}/os/emt/trusted-compute-os.json"
# Copy of the image config the EMT tarball was built from, saved by 'make build-microvisor-image'
TVM_EMT_BUILT_CONFIG="${TVM_ROOT_DIR}/build/microvisor_src/out/images/trusted-compute-os/trusted-compute-os.json"

TVM_OS_DESCRIPTION="Edge Microvisor Toolkit (EMT) rootfs and kernel"
TVM_OS_FEATURES=(gpu gpu-telemetry npu npu-telemetry debug)

os_feature_packages() {
    case "$1" in
        gpu)   echo "kernel-drivers-gpu linux-firmware-i915" ;;
        npu)   echo "intel-npu-driver intel-npu-firmware" ;;
        debug) echo "bc gawk igt-gpu-tools pciutils" ;;
    esac
}

# Packages installed on top of EMT minimal-os-packages: base config plus enabled features.
os_image_packages() {
    command -v yq > /dev/null || tvm_die "yq is required to read ${TVM_EMT_BASE_CONFIG}"
    {
        yq -p json -o yaml '.SystemConfigs[0].packages[]' "${TVM_EMT_BASE_CONFIG}"
        tvm_packages | tr ' ' '\n'
    } | sed '/^$/d' | sort -u | xargs
}

# Writes the EMT image config with packages for the enabled features to $1.
os_generate_image_config() {
    PKGS="$(os_image_packages)" yq -p json -o json -I 4 \
        '.SystemConfigs[0].packages = (strenv(PKGS) | split(" "))' \
        "${TVM_EMT_BASE_CONFIG}" > "$1"
}

# Fails unless the existing EMT tarball was built from the image config of the current selection.
os_check_base_image() {
    local current built_pkgs added removed
    [[ -f "${TVM_EMT_BUILT_CONFIG}" ]] \
        || tvm_die "cannot tell which selection the EMT image was built for; run 'make build-microvisor-image' first"
    current="$(mktemp)"
    os_generate_image_config "${current}"
    if cmp -s "${current}" "${TVM_EMT_BUILT_CONFIG}"; then
        rm -f "${current}"
        return 0
    fi
    rm -f "${current}"
    built_pkgs="$(yq -p json -o yaml '.SystemConfigs[0].packages[]' "${TVM_EMT_BUILT_CONFIG}" | sort -u)"
    added="$(comm -13 <(echo "${built_pkgs}") <(os_image_packages | tr ' ' '\n' | sort -u) | xargs)"
    removed="$(comm -23 <(echo "${built_pkgs}") <(os_image_packages | tr ' ' '\n' | sort -u) | xargs)"
    tvm_die "the EMT image was built for a different selection (missing: ${added:-none}; not wanted: ${removed:-none}); run 'make build-microvisor-image' or 'make build'"
}
