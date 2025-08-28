#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC3: Sample workload without TW deployment

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC3
sw_without_tw_deployment() {
    echo "=========================================="
    echo "TC3: Sample workload without TW deployment"
    echo "=========================================="
    
    install_sw_helm_chart 2>/dev/null
    pod_status=$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}')
    kubectl get pods ${SW_HELM_CHART_POD_NAME} -n "$SW_HELM_CHART_NAMESPACE"
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "INFO: Sample workload installation failed as expected without TW deployment"
        echo -e "RESULT: Sample workload without TW deployment [ successful ]\n"
    else
        echo "ERROR: Sample workload deployment sucessfull without TW deployment"
        echo "RESULT: Sample workload installation without TW deployment [ failed ]"
    fi
    uninstall_sw_helm_chart &>/dev/null
}

################
# Main Function
################
# Only run setup if executed directly (not from run_tests.sh)
if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_cluster_config "${1:-}"
    check_cluster_status
fi
echo "---------------------------------------------------"

check_existing_sw_helm_chart || { exit 1; }
wait_for_process 60 10 "[[ -z \$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep '$SW_HELM_CHART_POD_NAME') ]]" || {
    echo "ERROR: $SW_HELM_CHART_NAME pods are not removed"; exit 1; }

uninstall_tw_helm_chart || { exit 1; }
echo ""

sw_without_tw_deployment
