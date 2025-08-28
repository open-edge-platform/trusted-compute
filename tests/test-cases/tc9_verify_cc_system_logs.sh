#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC9: Verify logs are accessible for all pods in confidential-containers-system namespace

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

TC_NAMESPACE="$TW_HELM_CHART_NAMESPACE"

sudo true

#TC9
verify_cc_system_logs() {
    local test_case_desc="Verify logs are accessible for all pods in $TC_NAMESPACE namespace"
    echo "==================================================================================="
    echo "$test_case_desc"
    echo "==================================================================================="

    local result="True"
    local expected_pod_count=3
    
    # Check if namespace exists
    if ! kubectl get namespace "$TC_NAMESPACE" &> /dev/null; then
        echo "ERROR: Namespace $TC_NAMESPACE does not exist"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi
    
    local pods_output=$(kubectl get pods -n "$TC_NAMESPACE" --no-headers 2>/dev/null)
    local pod_names=($(echo "$pods_output" | awk '{print $1}'))
    
    if [[ ${#pod_names[@]} -eq 0 ]]; then
        echo "ERROR: No pods found in namespace $TC_NAMESPACE"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi
    if [[ ${#pod_names[@]} -ne $expected_pod_count ]]; then
        echo "ERROR: Expected $expected_pod_count pods, but found ${#pod_names[@]}"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi
    
    echo "INFO: Verifying logs accessibility for each pod"
    local pods_with_logs=0
    
    for pod_name in "${pod_names[@]}"; do
        echo "INFO: Checking logs for pod: $pod_name"
        local pod_status=$(kubectl get pod "$pod_name" -n "$TC_NAMESPACE" --no-headers | awk '{print $3}')
        echo "INFO: Pod $pod_name status: $pod_status"
        local logs_retrieved=false 
        
        # Try multiple methods to retrieve logs
        if kubectl logs "$pod_name" -n "$TC_NAMESPACE" --tail=5 &> /dev/null; then
            echo "INFO: Successfully retrieved recent logs for $pod_name"
            echo "INFO: Sample logs from $pod_name:"
            kubectl logs "$pod_name" -n "$TC_NAMESPACE" --tail=5 | head -3 | sed 's/^/    /' | cut -c1-75
            logs_retrieved=true
        elif kubectl logs "$pod_name" -n "$TC_NAMESPACE" --previous &> /dev/null; then
            echo "INFO: Successfully retrieved previous logs for $pod_name"
            echo "INFO: Sample previous logs from $pod_name:"
            kubectl logs "$pod_name" -n "$TC_NAMESPACE" --previous --tail=5 | head -3 | sed 's/^/    /' | cut -c1-75
            logs_retrieved=true
        fi
        
        if [[ "$logs_retrieved" == true ]]; then
            ((pods_with_logs++))
        fi
        echo "----------------------------------------"
    done
    echo "INFO: Log accessibility verification summary:"
    echo "*********************************************"
    echo "INFO: Total pods checked: ${#pod_names[@]}"
    echo "INFO: Expected pods: $expected_pod_count"
    echo "INFO: Pods with accessible logs: $pods_with_logs"

    if [[ $pods_with_logs -eq $expected_pod_count ]] ; then
        echo "INFO: All pods in $TC_NAMESPACE namespace have accessible logs"
        echo -e "RESULT: ${test_case_desc} [ successful ]\n"
    else
        echo "ERROR: Some pods in $TC_NAMESPACE namespace do not have accessible logs"
        echo -e "RESULT: ${test_case_desc} [ failed ]\n"
        exit 1
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
#install_tw_helm_chart
if helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
    echo "INFO: $TW_HELM_CHART_NAME already exists, skipping installation"
else
    echo "INFO: $TW_HELM_CHART_NAME does not exist, installing it"
    install_tw_helm_chart || { exit 1; }
fi
verify_cc_system_logs
