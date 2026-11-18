#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Select Trusted-VM image features in an interactive menu, or edit the config file.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/tvm_config_lib.sh"

usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Selects the features of the Trusted-VM image. Use --gui, or edit the config file
(default: ${TVM_USER_CONFIG}) by hand. Without options it prints the current configuration.

Options:
  -c, --config FILE          Config file to load and update
      --gui                  Interactive menu (whiptail or dialog)
      --defaults             Reset the config file to configs/defconfig (all features except debug)
      --show                 Print the configuration without writing it
  -h, --help                 Show this help

Build-internal options:
  -o, --output FILE          Write the resolved configuration to FILE
      --env                  Apply TVM_* environment overrides (same keys as the config file)
      --gen-image-config F   Write the OS image config (e.g. EMT JSON) to F
EOF
}

gui_cancel() {
    tvm_log "Menu cancelled, ${config_file} not changed"
    exit 0
}

run_gui() {
    local ui oses=() os_args=() feat_args=() id choice os
    if command -v whiptail > /dev/null; then
        ui=whiptail
    elif command -v dialog > /dev/null; then
        ui=dialog
    else
        tvm_die "whiptail or dialog is required for --gui; edit ${TVM_USER_CONFIG} instead"
    fi
    [[ -t 0 && -t 1 ]] || tvm_die "--gui needs an interactive terminal"

    mapfile -t oses < <(tvm_list_os)
    if (( ${#oses[@]} > 1 )); then
        for os in "${oses[@]}"; do
            os_args+=("${os}" "" "$([[ "${os}" == "${TVM_OS}" ]] && echo ON || echo OFF)")
        done
        TVM_OS="$("${ui}" --title "Trusted-VM image" --radiolist "Guest OS" 15 60 "${#oses[@]}" \
            "${os_args[@]}" 3>&1 1>&2 2>&3)" || gui_cancel
        tvm_config_resolve
    fi

    for id in "${TVM_OS_FEATURES[@]}"; do
        tvm_feature_info "${id}"
        feat_args+=("${id}" "${_TVM_DESC}" "$(tvm_enabled "${id}" && echo ON || echo OFF)")
    done
    choice="$("${ui}" --title "Trusted-VM image features (${TVM_OS})" --separate-output \
        --checklist "Space toggles, Enter confirms. Telemetry needs its device support ticked." \
        18 95 "${#TVM_OS_FEATURES[@]}" "${feat_args[@]}" 3>&1 1>&2 2>&3)" || gui_cancel
    for id in $(tvm_all_features); do
        printf -v "$(tvm_feature_key "${id}")" n
    done
    for id in ${choice//\"/}; do
        printf -v "$(tvm_feature_key "${id}")" y
    done

    TVM_EXTRA_PACKAGES="$("${ui}" --title "Trusted-VM image" \
        --inputbox "Extra ${TVM_OS} packages to install (space separated, optional)" 10 70 \
        "${TVM_EXTRA_PACKAGES}" 3>&1 1>&2 2>&3)" || gui_cancel
}

config_file="${TVM_USER_CONFIG}"
output_file=""
use_defaults=no
use_env=no
gui=no
show_only=no
gen_image_config=""

while (( $# )); do
    case "$1" in
        -c|--config)          config_file="$2"; shift ;;
        -o|--output)          output_file="$2"; shift ;;
        --defaults)           use_defaults=yes ;;
        --env)                use_env=yes ;;
        --gui)                gui=yes ;;
        --gen-image-config)   gen_image_config="$2"; shift ;;
        --show)               show_only=yes ;;
        -h|--help)            usage; exit 0 ;;
        *)                    usage >&2; tvm_die "unknown option '$1'" ;;
    esac
    shift
done

if [[ "${use_defaults}" == "yes" ]]; then
    tvm_config_load "" "${use_env}"
else
    tvm_config_load "${config_file}" "${use_env}"
fi

[[ "${gui}" == "no" ]] || run_gui
tvm_config_resolve

if [[ -n "${gen_image_config}" ]]; then
    os_generate_image_config "${gen_image_config}"
    tvm_log "Generated ${TVM_OS} image config: ${gen_image_config}"
fi

tvm_config_print

modified=no
if [[ "${use_defaults}" == "yes" || "${gui}" == "yes" || -n "${output_file}" ]]; then
    modified=yes
fi
if [[ "${show_only}" == "no" && "${modified}" == "yes" ]]; then
    tvm_config_write "${output_file:-${config_file}}"
    tvm_log "Configuration written to ${output_file:-${config_file}}"
fi
