#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Common functions for trusted workload component validation tests

set -uo pipefail
#set -x

# Configuration file path
COMMON_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$COMMON_SCRIPT_DIR/tw-component-validation-config.yaml"

# Load configuration variables
load_config() {
    # Trusted Workload Helm Chart Details
    TW_HELM_CHART_LINK=$(yq '.tw_helm_chart.chart_link' "$CONFIG_FILE")
    TW_HELM_CHART_NAME=$(yq '.tw_helm_chart.name' "$CONFIG_FILE")
    TW_HELM_CHART_NAMESPACE=$(yq '.tw_helm_chart.namespace' "$CONFIG_FILE")
    TW_HELM_CHART_VER=$(yq '.tw_helm_chart.version' "$CONFIG_FILE")
    TW_HELM_CHART_PREV_VER=$(yq '.tw_helm_chart.previous_version' "$CONFIG_FILE")
    TW_HELM_CHART_LOCAL=$(yq '.tw_helm_chart.local_chart' "$CONFIG_FILE")
    TW_HELM_CHART_FILE=$(yq '.tw_helm_chart.file_name' "$CONFIG_FILE")
    
    # Set variables to empty string if they are null
    [[ "$TW_HELM_CHART_LOCAL" == "null" ]] && TW_HELM_CHART_LOCAL=""
    [[ "$TW_HELM_CHART_FILE" == "null" ]] && TW_HELM_CHART_FILE=""
    
    # Export variables for use in test cases
    export TW_HELM_CHART_LINK TW_HELM_CHART_NAME TW_HELM_CHART_NAMESPACE TW_HELM_CHART_VER TW_HELM_CHART_PREV_VER
    [[ -n "$TW_HELM_CHART_LOCAL" ]] && export TW_HELM_CHART_LOCAL
    [[ -n "$TW_HELM_CHART_FILE" ]] && export TW_HELM_CHART_FILE

    # Sample workload chart details
    SW_HELM_CHART_LINK=$(yq '.sample_workload.chart_link' "$CONFIG_FILE")
    SW_HELM_CHART_NAME=$(yq '.sample_workload.name' "$CONFIG_FILE")
    SW_HELM_CHART_NAMESPACE=$(yq '.sample_workload.namespace' "$CONFIG_FILE")
    SW_HELM_CHART_VER=$(yq '.sample_workload.version' "$CONFIG_FILE")
    SW_HELM_CHART_TLS=$(yq '.sample_workload.skip_tls_verify' "$CONFIG_FILE")
    SW_HELM_CHART_POD_NAME=$(yq '.sample_workload.pod_name' "$CONFIG_FILE")
    SW_HELM_CHART_LOCAL=$(yq '.sample_workload.local_chart' "$CONFIG_FILE")
    SW_HELM_CHART_FILE=$(yq '.sample_workload.file_name' "$CONFIG_FILE")
    
    # Set variables to empty string if they are null
    [[ "$SW_HELM_CHART_LOCAL" == "null" ]] && SW_HELM_CHART_LOCAL=""
    [[ "$SW_HELM_CHART_FILE" == "null" ]] && SW_HELM_CHART_FILE=""

    # Export variables for use in test cases
    export SW_HELM_CHART_LINK SW_HELM_CHART_NAME SW_HELM_CHART_NAMESPACE 
    export SW_HELM_CHART_VER SW_HELM_CHART_TLS SW_HELM_CHART_POD_NAME
    [[ -n "$SW_HELM_CHART_LOCAL" ]] && export SW_HELM_CHART_LOCAL
    [[ -n "$SW_HELM_CHART_FILE" ]] && export SW_HELM_CHART_FILE
}

wait_for_process() {
    local wait_time="$1" sleep_time="$2" cmd="$3"
    while (( wait_time > 0 )); do
        eval "$cmd" && return 0 || sleep "$sleep_time"
        (( wait_time -= sleep_time ))
    done
    return 1
}

setup_cluster_config() {
    echo "cluster config"
    echo "--------------"
    echo "INFO: Setting up cluster configuration"

    local CLUSTER_CONFIG_FILE=$( [[ -n "${1:-}" && -f "$1" ]] && realpath "$1" || echo "" )
    
    if [[ -z "$CLUSTER_CONFIG_FILE" ]]; then
        echo "INFO: Using default configuration $HOME/.kube/config"
    else
        echo "INFO: Using provided cluster config file: $CLUSTER_CONFIG_FILE"
        export KUBECONFIG="$CLUSTER_CONFIG_FILE"
    fi
    echo ""
}

check_cluster_status() {
    echo "cluster status"
    echo "--------------"

    echo "INFO: Checking cluster status"
    kubectl cluster-info | head -n 1 || { echo "ERROR: Cluster is not running"; exit 1; }
    echo "INFO: Cluster is running"

    echo "INFO: Checking node readiness"
    wait_for_process 180 10 "kubectl get nodes | grep -q '\<Ready\>'" || { echo "ERROR: Nodes are not ready"; exit 1; }
    echo "INFO: Nodes are ready"

    echo "INFO: Checking and untainting nodes"
    if kubectl get nodes -o json | jq -e '.items[].spec.taints == null' > /dev/null; then
        echo "INFO: Nodes are untainted correctly"
    else
        echo "ERROR: Unexpected taints found on nodes"; exit 1;
    fi
    echo ""
}

check_existing_sw_helm_chart() {
    echo "INFO: Checking if sample workload is installed"
    if helm list -n $SW_HELM_CHART_NAMESPACE | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        [[ -n "${1:-}" && "${1:-}" == "skip" ]] && { echo "INFO: $SW_HELM_CHART_NAME exists, skipping installation"; return 0; }
        echo "INFO: $SW_HELM_CHART_NAME exists, uninstalling it"
        uninstall_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_NAMESPACE" || { exit 1; }
    else
        echo "INFO: $SW_HELM_CHART_NAME is not installed."
    fi
}

check_existing_tw_helm_chart() {
    echo "INFO: Checking if trusted-workload is installed"
    if helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        [[ -n "${1:-}" && "${1:-}" == "skip" ]] && { echo "INFO: $TW_HELM_CHART_NAME exists, skipping installation"; return 0; }
        echo "INFO: $TW_HELM_CHART_NAME exists, uninstalling it"
        uninstall_tw_helm_chart "$TW_HELM_CHART_NAMESPACE" || { exit 1; }
    else
        echo "INFO: $TW_HELM_CHART_NAME is not installed."
    fi
}

install_helm_chart() {
    local chart_name="${1}" chart_ns="${2}" chart_local="${3}"
    if [[ "$chart_local" == true ]]; then
        echo "INFO: Installing $chart_name helm chart from local file"
        local chart_file="${4}"
        [[ ! -f "$chart_file" ]] && { echo "ERROR: Local chart file $chart_file not found"; return 1; }
        helm install "$chart_name" "$chart_file" --create-namespace -n $chart_ns || { echo "ERROR: Failed to install $chart_name from local file"; return 1; }
    else
        local chart_link="${4}" chart_version="${5}"
        [[ -z "$chart_link" || -z "$chart_version" ]] && { echo "ERROR: Chart link or version not provided"; return 1; }
        echo "INFO: Installing $chart_name helm chart registry"
        helm install "$chart_name" "$chart_link" --version "$chart_version" --create-namespace -n $chart_ns $([[ ${6} == true ]] && echo "--insecure-skip-tls-verify") || \
        { echo "INFO: Failed to install $chart_name from registry"; return 1; }
    fi
    echo "INFO: $chart_name is installed"
    return 0
}

uninstall_helm_chart() {
    local chart_name="${1}" chart_ns="${2}"
    echo "INFO: Uninstalling $chart_name helm chart"

    local output=$(helm uninstall "$chart_name" -n $chart_ns 2>&1)
    if [[ $? -ne 0 ]]; then
        if [[ "$output" == *"uninstall: Failed to purge the release: release: not found"* ]]; then
            echo "INFO: $chart_name release not found, nothing to uninstall"
        else
            echo "$output"
            echo "ERROR: Failed to uninstall $chart_name helm chart"
            exit 1
        fi
    fi
    echo "INFO: $chart_name is uninstalled"
    return 0
}

install_tw_helm_chart() {
    #check if version is provided as argument
    [[ -n "${1:-}" && "${1:-}" != "-" ]] && local TW_HELM_CHART_VER="$1"
        
    install_helm_chart "$TW_HELM_CHART_NAME" "$TW_HELM_CHART_NAMESPACE" "$TW_HELM_CHART_LOCAL" \
        "$([[ "$TW_HELM_CHART_LOCAL" == "true" ]] && echo "$TW_HELM_CHART_FILE" || echo "$TW_HELM_CHART_LINK")" \
        "$([[ "$TW_HELM_CHART_LOCAL" != "true" ]] && echo "$TW_HELM_CHART_VER")" "false" || { return 1; }

    echo "INFO: Verifying TW deployment status"
    
    # First wait for all pods to be spawned
    wait_for_process 300 10 "[[ \$(kubectl get pods -n $TW_HELM_CHART_NAMESPACE --no-headers | wc -l) -eq 3 ]]" || {
        echo "ERROR: All TW deployment pods are not spawned"; return 1; 
    }
    
    # Then wait for all pods to be in Running or Completed state
    wait_for_process 300 10 "[[ -z \$(kubectl get pods -n $TW_HELM_CHART_NAMESPACE --no-headers | awk '{print \$3}' | grep -v -E 'Running|Completed') ]]" || {
        echo "ERROR: TW deployment pods are not in Running or Completed state"; return 1; 
    }

    echo "INFO: Verifying TW deployment readiness"
    if ! kubectl get pods -n $TW_HELM_CHART_NAMESPACE; then
        echo "ERROR: Failed to retrieve TW deployment pods"
        return 1
    fi
    return 0
}

uninstall_tw_helm_chart() {
    if ! helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        echo "INFO: $TW_HELM_CHART_NAME does not exist, nothing to uninstall"
        return 0
    fi
    
    uninstall_helm_chart "$TW_HELM_CHART_NAME" "$TW_HELM_CHART_NAMESPACE" || { return 1; }
    echo "INFO: Ensuring TW deployment pods are removed from the cluster"
    wait_for_process 300 10 "[[ -z \$(kubectl get pods -n $TW_HELM_CHART_NAMESPACE --no-headers) ]]" || {
        echo "ERROR: TW deployment pods are not removed"; return 1; }
    
    echo "INFO: TW deployment pods are removed from the cluster"
    for ((i=1; i<=2; i++)); do
        echo "INFO: Cleaning up..."
        sleep 20
    done
    return 0
}

install_sw_helm_chart()
{
    if [[ "$SW_HELM_CHART_LOCAL" == true ]]; then
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_NAMESPACE" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_FILE" 2>/dev/null
    else
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_NAMESPACE" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_LINK" "$SW_HELM_CHART_VER" "$SW_HELM_CHART_TLS" 2>/dev/null
    fi

    if [[ $? -eq 0 ]]; then
        chart_status=$(helm status "$SW_HELM_CHART_NAME" -n "$SW_HELM_CHART_NAMESPACE" --output json | jq -r '.info.status' 2>/dev/null || echo "unknown")
        if [[ "$chart_status" != "deployed" ]]; then echo "ERROR: Sample workload installation failed"; return 1; fi
    fi

    echo "INFO: checking the status of $SW_HELM_CHART_POD_NAME pod"
    wait_for_process 60 10 "[[ -z \$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep -w '$SW_HELM_CHART_POD_NAME' | awk '{print \$3}' | grep -v -E 'Running|Completed') ]]"
    pod_status=$(kubectl get pods -n "$SW_HELM_CHART_NAMESPACE" --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}')
    kubectl get pods ${SW_HELM_CHART_POD_NAME} -n "$SW_HELM_CHART_NAMESPACE"
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "INFO: $SW_HELM_CHART_NAME pods are in $pod_status state"; return 1;
    else
        echo "INFO: $SW_HELM_CHART_NAME pods are in $pod_status state"
    fi
}

uninstall_sw_helm_chart() {
    echo "INFO: uninstalling $SW_HELM_CHART_NAME helm chart"
    if helm list -n $SW_HELM_CHART_NAMESPACE | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        uninstall_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_NAMESPACE" || { exit 1; }
    fi
}

clean_system() {
    echo "INFO: Cleaning up system"
    if helm list -n $SW_HELM_CHART_NAMESPACE | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        uninstall_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_NAMESPACE" || { exit 1; }
    fi

    if helm list -n $TW_HELM_CHART_NAMESPACE | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        uninstall_tw_helm_chart || { exit 1; }
    fi
}

# Initialize configuration when sourced
load_config
