#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Trusted-VM build configuration library; source it, do not execute it.
# Config files contain KEY=value lines. Precedence: TVM_* env > config file > configs/defconfig.

TVM_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TVM_DEFCONFIG="${TVM_ROOT_DIR}/configs/defconfig"
TVM_USER_CONFIG="${TVM_ROOT_DIR}/.tvm.config"

# id|config key|required feature|description  (required features must be listed first)
TVM_FEATURE_TABLE=(
    "gpu|TVM_GPU||GPU support: GPU drivers, i915 firmware, scan-for-gpu OCI hook"
    "gpu-telemetry|TVM_GPU_TELEMETRY|gpu|GPU telemetry agent: qmassa, qmmd, jq"
    "npu|TVM_NPU||NPU support: intel-npu driver and firmware"
    "npu-telemetry|TVM_NPU_TELEMETRY|npu|NPU telemetry agent: npu-reader"
    "debug|TVM_DEBUG||Debug tools: bc, gawk, igt-gpu-tools, pciutils"
)

tvm_log()  { echo "INFO: $*" >&2; }
tvm_warn() { echo "WARNING: $*" >&2; }
tvm_die()  { echo "ERROR: $*" >&2; exit 1; }

tvm_all_features() {
    local row
    for row in "${TVM_FEATURE_TABLE[@]}"; do echo "${row%%|*}"; done
}

# Sets _TVM_KEY, _TVM_REQUIRES and _TVM_DESC for feature $1.
tvm_feature_info() {
    local row id
    for row in "${TVM_FEATURE_TABLE[@]}"; do
        IFS='|' read -r id _TVM_KEY _TVM_REQUIRES _TVM_DESC <<< "${row}"
        [[ "${id}" == "$1" ]] && return 0
    done
    return 1
}

tvm_feature_key() {
    tvm_feature_info "$1" || tvm_die "unknown feature '$1' (known: $(tvm_all_features | xargs))"
    echo "${_TVM_KEY}"
}

tvm_config_keys() {
    local id
    echo TVM_OS
    for id in $(tvm_all_features); do tvm_feature_key "${id}"; done
    echo TVM_EXTRA_PACKAGES
}

tvm_is_config_key() {
    local key
    for key in $(tvm_config_keys); do
        [[ "${key}" == "$1" ]] && return 0
    done
    return 1
}

tvm_list_os() {
    local dir name
    for dir in "${TVM_ROOT_DIR}"/os/*/; do
        name="$(basename "${dir}")"
        [[ -f "${dir}${name}_profile.sh" ]] && echo "${name}"
    done
}

tvm_enabled() {
    local key
    key="$(tvm_feature_key "$1")"
    [[ "${!key:-n}" == "y" ]]
}

tvm_os_supports() {
    [[ " ${TVM_OS_FEATURES[*]} " == *" $1 "* ]]
}

_tvm_config_read() {
    local file="$1" line key value n=0
    local re_skip='^[[:space:]]*(#|$)' re_kv='^[[:space:]]*([A-Z_]+)=(.*)$'
    while IFS= read -r line || [[ -n "${line}" ]]; do
        n=$((n + 1))
        [[ "${line}" =~ ${re_skip} ]] && continue
        [[ "${line}" =~ ${re_kv} ]] || tvm_die "${file}:${n}: invalid line: ${line}"
        key="${BASH_REMATCH[1]}"
        value="${BASH_REMATCH[2]}"
        tvm_is_config_key "${key}" || tvm_die "${file}:${n}: unknown option ${key}"
        value="${value%\"}"
        value="${value#\"}"
        printf -v "${key}" '%s' "${value}"
    done < "${file}"
}

_tvm_os_load() {
    local profile="${TVM_ROOT_DIR}/os/${TVM_OS}/${TVM_OS}_profile.sh"
    [[ "${TVM_OS}" =~ ^[a-z0-9-]+$ && -f "${profile}" ]] \
        || tvm_die "unsupported TVM_OS '${TVM_OS}' (available: $(tvm_list_os | xargs))"
    unset -f os_feature_packages os_image_packages os_generate_image_config
    source "${profile}"
}

# Normalises values, loads the OS definition and applies feature dependencies.
tvm_config_resolve() {
    local id key pkg pkgs=()
    for id in $(tvm_all_features); do
        key="$(tvm_feature_key "${id}")"
        case "${!key:-}" in
            y|Y|yes|true|1) printf -v "${key}" y ;;
            n|N|no|false|0|"") printf -v "${key}" n ;;
            *) tvm_die "${key} must be y or n, got '${!key}'" ;;
        esac
    done

    _tvm_os_load

    for id in $(tvm_all_features); do
        tvm_feature_info "${id}"
        key="${_TVM_KEY}"
        [[ "${!key}" == "y" ]] || continue
        if ! tvm_os_supports "${id}"; then
            tvm_warn "feature '${id}' is not supported on OS '${TVM_OS}', disabling it"
            printf -v "${key}" n
        elif [[ -n "${_TVM_REQUIRES}" ]] && ! tvm_enabled "${_TVM_REQUIRES}"; then
            tvm_warn "feature '${id}' requires '${_TVM_REQUIRES}', disabling it"
            printf -v "${key}" n
        fi
    done

    for pkg in ${TVM_EXTRA_PACKAGES//,/ }; do
        [[ "${pkg}" =~ ^[A-Za-z0-9][A-Za-z0-9._+-]*$ ]] || tvm_die "invalid package name '${pkg}'"
        pkgs+=("${pkg}")
    done
    TVM_EXTRA_PACKAGES="${pkgs[*]}"
}

# tvm_config_load [config file] [use env: yes|no]
tvm_config_load() {
    local file="${1:-}" use_env="${2:-yes}" key
    local -A env_vals=()
    for key in $(tvm_config_keys); do
        [[ "${use_env}" == "yes" && -n "${!key+x}" ]] && env_vals["${key}"]="${!key}"
        unset "${key}"
    done
    _tvm_config_read "${TVM_DEFCONFIG}"
    if [[ -n "${file}" && -f "${file}" ]]; then
        _tvm_config_read "${file}"
    fi
    for key in "${!env_vals[@]}"; do printf -v "${key}" '%s' "${env_vals[${key}]}"; done
    tvm_config_resolve
}

tvm_config_write() {
    local file="$1" id
    mkdir -p "$(dirname "${file}")"
    {
        echo "# Trusted-VM image configuration. Edit y/n values, or run 'make menuconfig'."
        echo "# A telemetry feature needs its device support (gpu / npu) enabled."
        echo ""
        echo "# Guest OS: $(tvm_list_os | xargs)"
        echo "TVM_OS=${TVM_OS}"
        for id in $(tvm_all_features); do
            tvm_feature_info "${id}"
            echo ""
            echo "# ${_TVM_DESC}"
            echo "${_TVM_KEY}=${!_TVM_KEY}"
        done
        echo ""
        echo "# Extra ${TVM_OS} packages to install, space separated"
        echo "TVM_EXTRA_PACKAGES=\"${TVM_EXTRA_PACKAGES}\""
    } > "${file}"
}

# Writes the feature/package record that is installed in the guest rootfs.
tvm_manifest_write() {
    local file="$1" packages
    packages="$(os_image_packages)"
    mkdir -p "$(dirname "${file}")"
    {
        echo "# Trusted-VM image features and packages added on top of the ${TVM_OS} base package list"
        echo "TVM_VERSION=$(tr -d '[:space:]' < "${TVM_ROOT_DIR}/../trusted-workload/VERSION")"
        echo "TVM_BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        _tvm_config_lines
        echo "TVM_PACKAGES=\"${packages}\""
    } > "${file}"
}

_tvm_config_lines() {
    local key
    for key in $(tvm_config_keys); do
        if [[ "${key}" == "TVM_EXTRA_PACKAGES" ]]; then
            echo "${key}=\"${!key}\""
        else
            echo "${key}=${!key}"
        fi
    done
}

# Prints the OS package list for the enabled features plus TVM_EXTRA_PACKAGES.
tvm_packages() {
    local id pkgs=() more=()
    for id in "${TVM_OS_FEATURES[@]}"; do
        if tvm_enabled "${id}"; then
            read -ra more <<< "$(os_feature_packages "${id}")"
            pkgs+=("${more[@]}")
        fi
    done
    read -ra more <<< "${TVM_EXTRA_PACKAGES}"
    pkgs+=("${more[@]}")
    echo "${pkgs[*]}"
}

tvm_config_print() {
    local id state
    echo "Trusted-VM build configuration"
    echo "  OS               : ${TVM_OS} (${TVM_OS_DESCRIPTION})"
    for id in $(tvm_all_features); do
        tvm_feature_info "${id}"
        state="$(tvm_enabled "${id}" && echo enabled || echo disabled)"
        tvm_os_supports "${id}" || state="unsupported"
        printf "  %-17s: %-11s %s\n" "${id}" "${state}" "${_TVM_DESC}"
    done
    echo "  extra packages   : ${TVM_EXTRA_PACKAGES:-<none>}"
    echo "  OS packages      : $(tvm_packages)"
}
