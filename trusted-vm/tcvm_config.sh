#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Select Trusted-VM image features in an interactive menu, or edit the config file.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/scripts/tcvm_config_lib.sh"

usage() {
    cat << EOF
Usage: $(basename "$0") [options]

Selects the features of the Trusted-VM image. Use --gui, or edit the config file
(default: ${TCVM_USER_CONFIG}) by hand. Without options it prints the current configuration.

Options:
  -c, --config FILE          Config file to load and update
      --gui                  Interactive menu (whiptail or dialog)
      --defaults             Reset the config file to configs/defconfig (all features except custom)
      --show                 Print the configuration without writing it
  -h, --help                 Show this help

Build-internal options:
  -o, --output FILE          Write the resolved configuration to FILE
      --gen-image-config F   Write the OS image config (e.g. EMT JSON) to F
      --check-base-image     Fail unless the existing base OS image was built for this configuration
EOF
}

gui_cancel() {
    tcvm_log "Menu cancelled, ${config_file} not changed"
    exit 0
}

run_gui() {
    local ui oses=() os_args=() feat_args=() id choice os
    if command -v whiptail > /dev/null; then
        ui=whiptail
    elif command -v dialog > /dev/null; then
        ui=dialog
    else
        tcvm_die "whiptail or dialog is required for --gui; edit ${TCVM_USER_CONFIG} instead"
    fi
    [[ -t 0 && -t 1 ]] || tcvm_die "--gui needs an interactive terminal"

    mapfile -t oses < <(tcvm_list_os)
    if (( ${#oses[@]} > 1 )); then
        for os in "${oses[@]}"; do
            os_args+=("${os}" "" "$([[ "${os}" == "${TCVM_OS}" ]] && echo ON || echo OFF)")
        done
        TCVM_OS="$("${ui}" --title "Trusted-VM image" --radiolist "Guest OS" 15 60 "${#oses[@]}" \
            "${os_args[@]}" 3>&1 1>&2 2>&3)" || gui_cancel
        tcvm_config_resolve
    fi

    for id in "${TCVM_OS_FEATURES[@]}"; do
        tcvm_feature_info "${id}"
        feat_args+=("${id}" "${_TCVM_DESC}" "$(tcvm_enabled "${id}" && echo ON || echo OFF)")
    done
    choice="$("${ui}" --title "Trusted-VM image features (${TCVM_OS})" --separate-output \
        --checklist "Space toggles, Enter confirms. Telemetry needs its device support ticked." \
        18 95 "${#TCVM_OS_FEATURES[@]}" "${feat_args[@]}" 3>&1 1>&2 2>&3)" || gui_cancel
    for id in $(tcvm_all_features); do
        printf -v "$(tcvm_feature_key "${id}")" n
    done
    for id in ${choice//\"/}; do
        printf -v "$(tcvm_feature_key "${id}")" y
    done

    if tcvm_enabled custom; then
        TCVM_CUSTOM_PACKAGES="$("${ui}" --title "Trusted-VM image" \
            --inputbox "Custom ${TCVM_OS} packages to install (space separated)" 10 70 \
            "${TCVM_CUSTOM_PACKAGES}" 3>&1 1>&2 2>&3)" || gui_cancel
    fi
}

config_file="${TCVM_USER_CONFIG}"
output_file=""
use_defaults=no
gui=no
show_only=no
gen_image_config=""
check_base_image=no

while (( $# )); do
    case "$1" in
        -c|--config|-o|--output|--gen-image-config)
            if (( $# < 2 )) || [[ -z "$2" ]]; then
                usage >&2; tcvm_die "option '$1' requires a file argument"
            fi ;;
    esac
    case "$1" in
        -c|--config)          config_file="$2"; shift ;;
        -o|--output)          output_file="$2"; shift ;;
        --defaults)           use_defaults=yes ;;
        --gui)                gui=yes ;;
        --gen-image-config)   gen_image_config="$2"; shift ;;
        --check-base-image)   check_base_image=yes ;;
        --show)               show_only=yes ;;
        -h|--help)            usage; exit 0 ;;
        *)                    usage >&2; tcvm_die "unknown option '$1'" ;;
    esac
    shift
done

if [[ "${use_defaults}" == "yes" ]]; then
    tcvm_config_load ""
else
    tcvm_config_load "${config_file}"
fi

[[ "${gui}" == "no" ]] || run_gui
tcvm_config_resolve

if [[ "${check_base_image}" == "yes" ]]; then
    os_check_base_image
    tcvm_log "Base ${TCVM_OS} image matches the configuration"
    exit 0
fi

if [[ -n "${gen_image_config}" ]]; then
    os_generate_image_config "${gen_image_config}"
    tcvm_log "Generated ${TCVM_OS} image config: ${gen_image_config}"
    exit 0
fi

tcvm_config_print

modified=no
if [[ "${use_defaults}" == "yes" || "${gui}" == "yes" || -n "${output_file}" ]]; then
    modified=yes
fi
if [[ "${show_only}" == "no" && "${modified}" == "yes" ]]; then
    if [[ -n "${output_file}" ]]; then
        tcvm_config_write "${output_file}" yes
    else
        tcvm_config_write "${config_file}"
    fi
    tcvm_log "Configuration written to ${output_file:-${config_file}}"
fi
