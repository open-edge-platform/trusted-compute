#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC8: Verify TW upgrade

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"
previous_version=$TW_HELM_CHART_PREV_VER

sudo true

#TC8
verify_tw_upgrade() {
    echo "======================"
    echo "TC8: Verify TW upgrade"
    echo "======================"

    clean_system #> /dev/null 2>&1
    echo "INFO: installing TW helm chart with version $previous_version"
    if ! install_tw_helm_chart $previous_version; then
        echo "ERROR: Failed to install TW helm chart with version $previous_version"
        echo "RESULT:  Verify TW upgrade [ failed ]"
        exit 1
    fi
    if ! uninstall_tw_helm_chart; then
        echo "ERROR: Failed to uninstall TW helm chart with version $previous_version"
        echo "RESULT: Verify TW upgrade [ failed ]"
        exit 1
    fi

    echo "INFO: installing TW helm chart with version $TW_HELM_CHART_VER"
    if ! install_tw_helm_chart $TW_HELM_CHART_VER; then
        echo "ERROR: Failed to install TW helm chart with version $TW_HELM_CHART_VER"
        echo "RESULT:  Verify TW upgrade [ failed ]"
        exit 1
    fi
    if ! uninstall_tw_helm_chart; then 
        echo "ERROR: Failed to uninstall TW helm chart with version $TW_HELM_CHART_VER"
        echo "RESULT: Verify TW upgrade [ failed ]"
        exit 1
    fi
    echo "RESULT:  Verify TW upgrade [ successful ]"
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
verify_tw_upgrade
