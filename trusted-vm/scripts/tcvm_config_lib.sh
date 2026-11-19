#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Trusted-VM build configuration library; source it, do not execute it.
# Config files contain KEY=value lines; values in the config file override configs/defconfig.

TCVM_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TCVM_DEFCONFIG="${TCVM_ROOT_DIR}/configs/defconfig"
TCVM_USER_CONFIG="${TCVM_ROOT_DIR}/.tcvm.config"
TCVM_BUILD_INFO_KEYS="TCVM_VERSION TCVM_BUILD_DATE TCVM_PACKAGES"

# id|config key|required feature|description  (required features must be listed first)
TCVM_FEATURE_TABLE=(
    "gpu|TCVM_GPU||GPU support: GPU drivers, i915 firmware, scan-for-gpu OCI hook"
    "gpu-telemetry|TCVM_GPU_TELEMETRY|gpu|GPU telemetry agent: qmassa, qmmd, jq"
    "npu|TCVM_NPU||NPU support: intel-npu driver and firmware"
    "npu-telemetry|TCVM_NPU_TELEMETRY|npu|NPU telemetry agent: npu-reader"
    "custom|TCVM_CUSTOM||Custom packages: listed in TCVM_CUSTOM_PACKAGES"
)

tcvm_log()  { echo "INFO: $*" >&2; }
tcvm_warn() { echo "WARNING: $*" >&2; }
tcvm_die()  { echo "ERROR: $*" >&2; exit 1; }

tcvm_all_features() {
    local row
    for row in "${TCVM_FEATURE_TABLE[@]}"; do echo "${row%%|*}"; done
}

# Sets _TCVM_KEY, _TCVM_REQUIRES and _TCVM_DESC for feature $1.
tcvm_feature_info() {
    local row id
    for row in "${TCVM_FEATURE_TABLE[@]}"; do
        IFS='|' read -r id _TCVM_KEY _TCVM_REQUIRES _TCVM_DESC <<< "${row}"
        [[ "${id}" == "$1" ]] && return 0
    done
    return 1
}

tcvm_feature_key() {
    tcvm_feature_info "$1" || tcvm_die "unknown feature '$1' (known: $(tcvm_all_features | xargs))"
    echo "${_TCVM_KEY}"
}

tcvm_config_keys() {
    local id
    echo TCVM_OS
    for id in $(tcvm_all_features); do tcvm_feature_key "${id}"; done
    echo TCVM_CUSTOM_PACKAGES
}

tcvm_is_config_key() {
    local key
    for key in $(tcvm_config_keys); do
        [[ "${key}" == "$1" ]] && return 0
    done
    return 1
}

tcvm_list_os() {
    local dir name
    for dir in "${TCVM_ROOT_DIR}"/os/*/; do
        name="$(basename "${dir}")"
        [[ -f "${dir}${name}_profile.sh" ]] && echo "${name}"
    done
}

tcvm_enabled() {
    local key
    key="$(tcvm_feature_key "$1")"
    [[ "${!key:-n}" == "y" ]]
}

tcvm_os_supports() {
    [[ " ${TCVM_OS_FEATURES[*]} " == *" $1 "* ]]
}

_tcvm_config_read() {
    local file="$1" line key value n=0
    local re_skip='^[[:space:]]*(#|$)' re_kv='^[[:space:]]*([A-Z_]+)=(.*)$'
    while IFS= read -r line || [[ -n "${line}" ]]; do
        n=$((n + 1))
        [[ "${line}" =~ ${re_skip} ]] && continue
        [[ "${line}" =~ ${re_kv} ]] || tcvm_die "${file}:${n}: invalid line: ${line}"
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        # Build info keys are regenerated on every write
        [[ " ${TCVM_BUILD_INFO_KEYS} " == *" ${key} "* ]] && continue
        tcvm_is_config_key "${key}" || tcvm_die "${file}:${n}: unknown option ${key}"
        value="${value%\"}"
        value="${value#\"}"
        printf -v "${key}" '%s' "${value}"
    done < "${file}"
}

_tcvm_os_load() {
    local profile="${TCVM_ROOT_DIR}/os/${TCVM_OS}/${TCVM_OS}_profile.sh"
    [[ "${TCVM_OS}" =~ ^[a-z0-9-]+$ && -f "${profile}" ]] \
        || tcvm_die "unsupported TCVM_OS '${TCVM_OS}' (available: $(tcvm_list_os | xargs))"
    unset -f os_feature_packages os_image_packages os_generate_image_config os_check_base_image
    source "${profile}"
}

# Normalises values, loads the OS definition and applies feature dependencies.
tcvm_config_resolve() {
    local id key pkg pkgs=() raw_pkgs=()
    for id in $(tcvm_all_features); do
        key="$(tcvm_feature_key "${id}")"
        case "${!key:-}" in
            y|Y|yes|true|1) printf -v "${key}" y ;;
            n|N|no|false|0|"") printf -v "${key}" n ;;
            *) tcvm_die "${key} must be y or n, got '${!key}'" ;;
        esac
    done

    _tcvm_os_load

    for id in $(tcvm_all_features); do
        tcvm_feature_info "${id}"
        key="${_TCVM_KEY}"
        [[ "${!key}" == "y" ]] || continue
        if ! tcvm_os_supports "${id}"; then
            tcvm_warn "feature '${id}' is not supported on OS '${TCVM_OS}', disabling it"
            printf -v "${key}" n
        elif [[ -n "${_TCVM_REQUIRES}" ]] && ! tcvm_enabled "${_TCVM_REQUIRES}"; then
            tcvm_warn "feature '${id}' requires '${_TCVM_REQUIRES}', disabling it"
            printf -v "${key}" n
        fi
    done

    read -r -a raw_pkgs <<< "${TCVM_CUSTOM_PACKAGES//,/ }"
    for pkg in "${raw_pkgs[@]}"; do
        [[ "${pkg}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || tcvm_die "invalid package name '${pkg}'"
        pkgs+=("${pkg}")
    done
    TCVM_CUSTOM_PACKAGES="${pkgs[*]}"
}

# tcvm_config_load [config file]
tcvm_config_load() {
    local file="${1:-}" key
    for key in $(tcvm_config_keys); do unset "${key}"; done
    _tcvm_config_read "${TCVM_DEFCONFIG}"
    if [[ -n "${file}" && -f "${file}" ]]; then
        _tcvm_config_read "${file}"
    fi
    tcvm_config_resolve
}

tcvm_config_write() {
    local file="$1" build_info="${2:-no}" id packages=""
    [[ "${build_info}" == "no" ]] || packages="$(os_image_packages)"
    mkdir -p "$(dirname "${file}")"
    {
        echo "# Trusted-VM image configuration. Edit y/n values, or run 'make menuconfig'."
        echo "# A telemetry feature needs its device support (gpu / npu) enabled."
        echo ""
        echo "# Guest OS: $(tcvm_list_os | xargs)"
        echo "TCVM_OS=${TCVM_OS}"
        for id in $(tcvm_all_features); do
            tcvm_feature_info "${id}"
            echo ""
            echo "# ${_TCVM_DESC}"
            echo "${_TCVM_KEY}=${!_TCVM_KEY}"
        done
        echo ""
        echo "# Packages installed when TCVM_CUSTOM=y, space separated"
        echo "TCVM_CUSTOM_PACKAGES=\"${TCVM_CUSTOM_PACKAGES}\""
        if [[ "${build_info}" == "yes" ]]; then
            echo ""
            echo "# Build information, generated at build time (read-only)"
            echo "TCVM_VERSION=$(tr -d '[:space:]' < "${TCVM_ROOT_DIR}/../trusted-workload/VERSION")"
            echo "TCVM_BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo "# Packages installed on top of the ${TCVM_OS} base package list"
            echo "TCVM_PACKAGES=\"${packages}\""
        fi
    } > "${file}"
}

# Prints the OS package list for the enabled features (custom: TCVM_CUSTOM_PACKAGES).
tcvm_packages() {
    local id pkgs=() more=()
    for id in "${TCVM_OS_FEATURES[@]}"; do
        tcvm_enabled "${id}" || continue
        if [[ "${id}" == "custom" ]]; then
            read -ra more <<< "${TCVM_CUSTOM_PACKAGES}"
        else
            read -ra more <<< "$(os_feature_packages "${id}")"
        fi
        pkgs+=("${more[@]}")
    done
    echo "${pkgs[*]}"
}

tcvm_config_print() {
    local id state
    echo "Trusted-VM build configuration"
    echo "  OS               : ${TCVM_OS} (${TCVM_OS_DESCRIPTION})"
    for id in $(tcvm_all_features); do
        tcvm_feature_info "${id}"
        state="$(tcvm_enabled "${id}" && echo enabled || echo disabled)"
        tcvm_os_supports "${id}" || state="unsupported"
        printf "  %-17s: %-11s %s\n" "${id}" "${state}" "${_TCVM_DESC}"
    done
    echo "  custom packages  : ${TCVM_CUSTOM_PACKAGES:-<none>}"
    echo "  OS packages      : $(tcvm_packages)"
}
