#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC7: Verify RBAC rules test case

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC7
verify_rbac_rules() {
    echo "================================"
    echo "TC7: Verify RBAC rules test case"
    echo "================================"

    local result="True"
    for role in get list; do
        local output=$(kubectl auth can-i $role customresourcedefinitions.apiextensions.k8s.io --as=system:serviceaccount:$TW_HELM_CHART_NAMESPACE:cc-operator-controller-manager)
        if [[ $output == "yes" ]]; then
            echo "INFO: RBAC allows '$role' on customresourcedefinitions for serviceaccount 'cc-operator-controller-manager' "
            echo ""
        else
            echo "ERROR: RBAC does NOT allow '$role' on customresourcedefinitions for serviceaccount 'cc-operator-controller-manager'"
            result="False"
        fi
    done

    if [[ $result == "True" ]]; then
        echo "INFO: RBAC rules are set correctly"
        echo "RESULT: Verify RBAC rules test case [ successful ]"
    else
        echo "ERROR: RBAC rules are not set correctly"
        echo "RESULT: Verify RBAC rules test case [ failed ]"
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
verify_rbac_rules
