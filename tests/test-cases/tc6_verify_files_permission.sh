#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC6: Verify files permission test case

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC6
verify_files_permission() {
    echo "======================================"
    echo "TC6: Verify files permission test case"
    echo "======================================"

    SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
    if [[ "$SERVER" =~ ^https://10\. || "$SERVER" =~ ^https://192\.168\. || "$SERVER" =~ ^https://127\.0\.0\.1 || "$SERVER" =~ ^https://localhost ]]; then
        echo "Local cluster: $SERVER"
    else
        echo "Remote cluster: $SERVER"
        echo "edge node not accessible, skipping file permission check"
        echo "RESULT: ${test_case_desc} [ skipped ]"
        echo ""
        return 0
    fi

    local permission_file="$PWD/../trusted-workload/kata-deploy/kata_keeplist.txt"
    local kernel_config=$(yq '.kernel.config' ../trusted-workload/kata-deploy/version.yaml)
    local kernel_name=$(yq '.kernel.name' ../trusted-workload/kata-deploy/version.yaml)

    local added_files=(
        "share/kata-containers/$kernel_config root:root 600"
        "share/kata-containers/vmlinux.container root:root 777"
        "share/kata-containers/kata-containers.img root:root 777"
        "share/kata-containers/$kernel_name root:bm-agents 640"
        "share/defaults/kata-containers/configuration.toml root:root 777"
    )

    local result="True"
    pushd "/opt/kata"
    # List all files/dirs with their owner:group and permissions
    while IFS= read -r line; do
    
        file_path=$(echo "$line" | awk '{print $1}' | sed 's|^\./||')
        [[ "$file_path" == "." ]] && continue
        owner_group=$(echo "$line" | awk '{print $2}')
        # If group is 500, change to bm-agents
        if [[ "$owner_group" =~ ^([^:]+):500$ ]]; then
            owner_group="${BASH_REMATCH[1]}:bm-agents"
        fi
        perms=$(echo "$line" | awk '{print $3}')
        search_string="$file_path $owner_group $perms"

        # Search for the exact full string in the permission file
        if ! grep -Fxq "$search_string" "$permission_file"; then
            if [[ " ${added_files[*]} " == *" $search_string "* ]]; then
                continue
            fi
            echo "ERROR: $search_string permission is not set correctly"
            result="False"
        fi
    done < <(sudo find . -printf '%p %u:%g %m\n')
    popd

    echo ""
    if [[ $result == "True" ]]; then
        echo "INFO: TW file and directory permissions are set correctly"
        echo "RESULT: Verify files permission test case [ successful ]"
    else
        echo "ERROR: TW file and directory permissions are not set correctly"
        echo "RESULT: Verify files permission test case [ failed ]"
    fi
    echo ""
}

################
# Main Function
################
if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_cluster_config "${1:-}"
    check_cluster_status
fi
echo "---------------------------------------------------"
#install_tw_helm_chart
if helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
    echo "INFO: $TW_HELM_CHART_NAME already exists, skipping installation"
else
    echo "INFO: $TW_HELM_CHART_NAME does not exist, installing it"
    install_tw_helm_chart || { exit 1; }
fi

verify_files_permission
