#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Edge Microvisor Toolkit guest OS definition, sourced by scripts/tvm_config_lib.sh.
# Every os/<name>/<name>_profile.sh must define TVM_OS_DESCRIPTION, TVM_OS_FEATURES,
# os_feature_packages, os_image_packages and os_generate_image_config.

TVM_EMT_BASE_CONFIG="${TVM_ROOT_DIR}/os/emt/trusted-compute-os.json"

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
