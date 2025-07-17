#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# TC5: Verify Kubernetes commands

set -uo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common_functions.sh"

sudo true

#TC5
verify_k8s_commands() {
    echo "==============================="
    echo "TC5: Verify Kubernetes commands"
    echo "==============================="

    pod_status=$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}')
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "ERROR: $SW_HELM_CHART_NAME pods are in $pod_status state"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi

    local result="True"
    echo "INFO: Verifying k8s command get"
    if ! kubectl get pods $SW_HELM_CHART_POD_NAME -n "$SW_HELM_CHART_NAMESPACE"; then
        echo "ERROR: kubectl get pods $SW_HELM_CHART_POD_NAME -n "$SW_HELM_CHART_NAMESPACE" failed"
        result="False"
    fi
    echo ""

    echo "INFO: Verifying k8s command describe"
    if ! kubectl get pod $SW_HELM_CHART_POD_NAME -n "$SW_HELM_CHART_NAMESPACE" -o json | jq '. | {
        "Podname": .metadata.name,
        "Namespace": .metadata.namespace,
        "Runtime Class Name": .spec.runtimeClassName,
        "Start Time": .metadata.creationTimestamp,
        "Image": .spec.containers[0].image,
        "Image Name": .spec.containers[0].name,
        "Container image": .status.containerStatuses[0].image,
        "NodeName: ": .spec.nodeName,
        "NodeSelectors": .spec.nodeSelector,
        "Pod status": (.status.conditions | last),
    }'; then
        echo "ERROR: Failed to retrieve JSON output for pod $SW_HELM_CHART_POD_NAME"
        result="False"
    fi

    echo "INFO: Verifying k8s command logs"
    if ! kubectl logs $SW_HELM_CHART_POD_NAME -n "$SW_HELM_CHART_NAMESPACE" --tail=5; then
        echo "ERROR: kubectl logs $SW_HELM_CHART_POD_NAME failed"
        result="False"
    fi

    echo ""
    [ $result == "True" ] && echo "RESULT: Verify Kubernetes commands [ successful ]" || echo "RESULT: Verify Kubernetes commands [ failed ]"
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

#install_sw_helm_chart
if helm list -n $SW_HELM_CHART_NAMESPACE | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
    echo "INFO: $SW_HELM_CHART_NAME already exists, skipping installation"
else
    echo "INFO: $SW_HELM_CHART_NAME does not exist, installing it"
    install_sw_helm_chart || { exit 1; }
fi

verify_k8s_commands
