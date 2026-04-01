#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -e  # Exit on any error
set -u  # Treat unset variables as an error
set -o pipefail  # Catch errors in piped commands

host_kata_dir="/host/opt/kata"
host_bin_dir="/host/usr/bin"
host_config_dir="/host/etc/kata-containers"


#help function
show_help() {
    echo "Usage: $0 [option]"
    echo "Options:"
    echo "  -r, remove      Remove Kata Containers installation"
    echo "  -i, install     Install Kata Containers"
    echo "  -h, help        Show this help message"
}

remove_artifacts() {
    echo "deleting kata artifacts"
    rm -rf "${host_kata_dir}"
    rm -f ${host_bin_dir}/containerd-shim-kata-v2
    rm -f ${host_config_dir}/configuration.toml
}

install_artifacts() {
    echo "copying kata artifacts onto host"
    mkdir -p ${host_kata_dir}
    mkdir -p ${host_config_dir}
    cp -au "/opt/kata-artifacts/opt/kata/"* "${host_kata_dir}/"
    cp ${host_kata_dir}/bin/containerd-shim-kata-v2  ${host_bin_dir}/containerd-shim-kata-v2
    cp ${host_kata_dir}/share/defaults/kata-containers/configuration.toml ${host_config_dir}/configuration.toml
}

#main script execution
main() {
    case "${1:-}" in
        -h|help)
            show_help
            exit 0
            ;;
        -r|remove)
            remove_artifacts
            echo "Kata Containers removed successfully."
            ;;
        -i|install)
            install_artifacts
            echo "Kata Containers Installation completed successfully."
            sleep infinity
            ;;
        *)
            if [ -z "${1:-}" ]; then
                echo "No argument provided."
            else
                echo "Invalid argument: $1"
            fi
            show_help
            exit 1
            ;;
    esac
}

main "$@"
