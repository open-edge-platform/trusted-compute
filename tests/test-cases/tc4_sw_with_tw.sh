#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC4: Sample workload with TW deployment

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC4
sw_with_tw_deployment() {
    echo "======================================="
    echo "TC4: Sample workload with TW deployment"
    echo "======================================="
    
    install_sw_helm_chart
    pod_status=$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}')
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "ERROR: $SW_HELM_CHART_NAME pods are in $pod_status state"
        echo -e "RESULT: Sample workload with TW deployment [ failed ]\n"
        return 1
    else
        echo "INFO: $SW_HELM_CHART_NAME pods are in $pod_status state"
        echo -e "RESULT: Sample workload with TW deployment [ successful ]\n"
        return 0
    fi
}

################
# Main Function
################
if [[ -z "${SKIP_SETUP:-}" ]]; then
    setup_cluster_config "${1:-}"
    check_cluster_status
fi
echo "---------------------------------------------------"
check_existing_sw_helm_chart || { exit 1; }
wait_for_process 60 10 "[[ -z \$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep '$SW_HELM_CHART_POD_NAME') ]]" || {
    echo "ERROR: $SW_HELM_CHART_NAME pods are not removed"; exit 1; }

if helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
    echo "INFO: $TW_HELM_CHART_NAME already exists, skipping installation"
else
    echo "INFO: $TW_HELM_CHART_NAME does not exist, installing it"
    install_tw_helm_chart "$TW_HELM_CHART_VER" || { exit 1; }
fi

sw_with_tw_deployment
