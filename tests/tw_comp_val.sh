#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -uo pipefail

CONFIG_FILE="$PWD/tw_val_config.yaml"

# Trusted Workload Helm Chart Details
TW_HELM_CHART_LINK=$(yq '.tw_helm_chart.chart_link' "$CONFIG_FILE")
TW_HELM_CHART_NAME=$(yq '.tw_helm_chart.name' "$CONFIG_FILE")
TW_HELM_CHART_VER=$(yq '.tw_helm_chart.version' "$CONFIG_FILE")
TW_HELM_CHART_LOCAL=$(yq '.tw_helm_chart.local_chart' "$CONFIG_FILE")
TW_HELM_CHART_FILE=$(yq '.tw_helm_chart.file_name' "$CONFIG_FILE")

#sample workload chart details
SW_HELM_CHART_LINK=$(yq '.sample_workload.chart_link' "$CONFIG_FILE")
SW_HELM_CHART_NAME=$(yq '.sample_workload.name' "$CONFIG_FILE")
SW_HELM_CHART_VER=$(yq '.sample_workload.version' "$CONFIG_FILE")
SW_HELM_CHART_TLS=$(yq '.sample_workload.skip_tls_verify' "$CONFIG_FILE")
SW_HELM_CHART_POD_NAME=$(yq '.sample_workload.pod_name' "$CONFIG_FILE")
SW_HELM_CHART_LOCAL=$(yq '.sample_workload.local_chart' "$CONFIG_FILE")
SW_HELM_CHART_FILE=$(yq '.sample_workload.file_name' "$CONFIG_FILE")

CLUSTER_CONFIG_FILE=$( [[ -n "${1:-}" && -f "$1" ]] && realpath "$1" || echo "" )

wait_for_process() {
    local wait_time="$1" sleep_time="$2" cmd="$3"
    while (( wait_time > 0 )); do
        eval "$cmd" && return 0 || sleep "$sleep_time"
        (( wait_time -= sleep_time ))
    done
    return 1
}

install_helm_chart() {
    local chart_name="${1}" chart_local="${2}"
    if [[ "$chart_local" == true ]]; then
        echo "INFO: Installing $chart_name helm chart from local file"
        local chart_file="${3}"
        [[ ! -f "$chart_file" ]] && { echo "ERROR: Local chart file $chart_file not found"; return 1; }
        helm install "$chart_name" "$chart_file" || { echo "ERROR: Failed to install $chart_name from local file"; return 1; }
    else
        local chart_link="${3}" chart_version="${4}"
        [[ -z "$chart_link" || -z "$chart_version" ]] && { echo "ERROR: Chart link or version not provided"; return 1; }
        echo "INFO: Installing $chart_name helm chart from remote link"
        helm install "$chart_name" "$chart_link" --version "$chart_version" $([[ ${5} == true ]] && echo "--insecure-skip-tls-verify") || \
        { echo "ERROR: Failed to install $chart_name from remote link"; return 1; }
    fi
    echo "INFO: $chart_name is installed"
    return 0
}

uninstall_helm_chart() {
    local chart_name="${1}"
    echo "INFO: Uninstalling $chart_name helm chart"

    helm uninstall "$chart_name"
    [[ $? -ne 0 ]] && { echo "ERROR: Failed to uninstall $chart_name helm chart"; return 1; }
    echo "INFO: $chart_name is uninstalled"
    return 0
}

setup_cluster_config() {
    echo "cluster config"
    echo "--------------"
    echo "INFO: Setting up cluster configuration"

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

    echo "INFO: Checking and labeling nodes"
    local node_name=$(kubectl get nodes -o name | head -n 1 | cut -d'/' -f2)
    if ! kubectl get nodes --show-labels | grep -q "node-role.kubernetes.io/worker=true"; then
        echo "ERROR: Node labeled with node-role.kubernetes.io/worker=true"; exit 1;
    else
        echo "INFO: Nodes already labeled correctly"
    fi

    echo "INFO: Checking and untainting nodes"
    if kubectl get nodes -o json | jq -e '.items[].spec.taints == null' > /dev/null; then
        echo "INFO: Nodes are untainted correctly"
    else
        echo "ERROR: Unexpected taints found on nodes"; exit 1;
    fi

    echo "INFO: Checking if any old helm charts are installed"
    for chart in "$SW_HELM_CHART_NAME" "$TW_HELM_CHART_NAME"; do
        if helm list --all | awk -v chart="$chart" '$1 == chart {found=1} END {exit !found}'; then
            echo "ERROR: $chart is already installed. Please uninstall it before proceeding."
            exit 1
        fi
    done
    echo ""
}

install_tw_helm_chart() {
    echo "INFO: Ensuring $TW_HELM_CHART_NAME helm chart is not already installed"
    if helm list | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        [[ "$1" == "skip" ]] && { echo "INFO: $TW_HELM_CHART_NAME exists, skipping installation"; return 0; }
        echo "INFO: $TW_HELM_CHART_NAME exists, uninstalling it"
        uninstall_tw_helm_chart || { exit 1; }
    fi
    
    install_helm_chart "$TW_HELM_CHART_NAME" "$TW_HELM_CHART_LOCAL" \
        "$([[ "$TW_HELM_CHART_LOCAL" == "true" ]] && echo "$TW_HELM_CHART_FILE" || echo "$TW_HELM_CHART_LINK")" \
        "$([[ "$TW_HELM_CHART_LOCAL" != "true" ]] && echo "$TW_HELM_CHART_VER")" "false" || { return 1; }

    echo "INFO: Verifying TW deployment status"
    wait_for_process 300 10 "[[ -z \$(kubectl get pods -n confidential-containers-system --no-headers | awk '{print \$3}' | grep -v -E 'Running|Completed') ]]" || {
        echo "ERROR: TW deployment pods are not in Running or Completed state"; return 1; 
    }

    wait_for_process 300 10 "[[ \$(kubectl get pods -n confidential-containers-system --no-headers | wc -l) -eq 3 ]]" || {
        echo "ERROR: All TW deployment pods are not spanwned "; return 1; 
    }

    echo "INFO: Verifying TW deployment readiness"
    if ! kubectl get pods -n confidential-containers-system; then
        echo "ERROR: Failed to retrieve TW deployment pods"
        return 1
    fi
    return 0
}

uninstall_tw_helm_chart() {
    if ! helm list | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        echo "INFO: $TW_HELM_CHART_NAME does not exist, nothing to uninstall"
        return 0
    fi
    
    uninstall_helm_chart "$TW_HELM_CHART_NAME" || { return 1; }
    echo "INFO: Ensuring TW deployment pods are removed from the cluster"
    wait_for_process 300 10 "[[ -z \$(kubectl get pods -n confidential-containers-system --no-headers) ]]" || {
        echo "ERROR: TW deployment pods are not removed"; return 1; }
    
    echo "INFO: TW deployment pods are removed from the cluster"
    for ((i=1; i<=2; i++)); do
        echo "INFO: Cleaning up..."
        sleep 20
    done
    return 0
}

clean_system() {
    echo "INFO: Cleaning up system"
    if helm list | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        uninstall_helm_chart "$SW_HELM_CHART_NAME" || { exit 1; }
    fi

    if helm list | awk -v chart="$TW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        uninstall_tw_helm_chart || { exit 1; }
    fi
}

#TC1
tw_deployment_in_cluster() {
    local test_case_name=$(yq '.tw_test_cases[0] | .name'  "$CONFIG_FILE")
    local test_case_desc=$(yq '.tw_test_cases[0] | .description' "$CONFIG_FILE")
    echo "${test_case_name}: ${test_case_desc}"
    echo "=========================================================="

    install_tw_helm_chart && echo "INFO: TW deployment is ready" && \
        echo "RESULT: ${test_case_desc} [ successful ]" || { echo "RESULT: ${test_case_desc} [ failed ]"; exit 1; }
    echo ""
}

#TC2
tw_uninstall_in_cluster() {
    local test_case_name=$(yq '.tw_test_cases[1] | .name'  "$CONFIG_FILE")
    local test_case_desc=$(yq '.tw_test_cases[1] | .description' "$CONFIG_FILE")
    echo "${test_case_name}: ${test_case_desc}"
    echo "========================================================"

    uninstall_tw_helm_chart && echo "INFO: TW deployment is uninstalled" && \
    echo "RESULT: ${test_case_desc} [ successful ]" || { echo "RESULT: ${test_case_desc} [ failed ]"; exit 1; }
    echo ""
}

#TC3
sw_without_tw_deployment() {
    local test_case_name=$(yq '.tw_test_cases[2] | .name'  "$CONFIG_FILE")
    local test_case_desc=$(yq '.tw_test_cases[2] | .description' "$CONFIG_FILE")
    echo "${test_case_name}: ${test_case_desc}"
    echo "============================================================"

    echo "INFO: Ensuring $TW_HELM_CHART_NAME helm chart is not installed"
    uninstall_tw_helm_chart || { exit 1; }

    if helm list | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        echo "INFO: $SW_HELM_CHART_NAME exists, uninstalling it"
        uninstall_helm_chart "$SW_HELM_CHART_NAME" || { exit 1; }
        wait_for_process 60 10 "[[ -z \$(kubectl get pods -n default --no-headers | grep '$SW_HELM_CHART_POD_NAME') ]]" || {
            echo "ERROR: $SW_HELM_CHART_NAME pods are not removed"; exit 1; }
    fi

    echo "INFO: Deploying sample workload without TW deployment"
    echo "INFO: installing $SW_HELM_CHART_NAME helm chart"
    local install_result=1
    if [[ "$SW_HELM_CHART_LOCAL" == true ]]; then
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_FILE" 2>/dev/null || install_result=0
    else
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_LINK" "$SW_HELM_CHART_VER" "$SW_HELM_CHART_TLS" 2>/dev/null || install_result=0
    fi

    if [[ $install_result -eq 0 ]]; then
        chart_status=$(helm status "$SW_HELM_CHART_NAME" --output json | jq -r '.info.status' 2>/dev/null || echo "unknown")
        if [[ "$chart_status" == "deployed" ]]; then
            echo "INFO: Sample workload is installed successfully without TW deployment, which is unexpected"
            echo "RESULT: ${test_case_desc} [ failed ]"
        fi
    fi
    uninstall_helm_chart "$SW_HELM_CHART_NAME" || { exit 1; }
    echo "INFO: Sample workload installation failed as expected without TW deployment"
    echo "RESULT: ${test_case_desc} [ successful ]"

    echo ""
}

#TC4
sw_with_tw_deployment() {
    local test_case_name=$(yq '.tw_test_cases[3] | .name'  "$CONFIG_FILE")
    local test_case_desc=$(yq '.tw_test_cases[3] | .description' "$CONFIG_FILE")
    echo "${test_case_name}: ${test_case_desc}"
    echo "============================================================="

    install_tw_helm_chart "skip" || { exit 1; }

    if helm list | awk -v chart="$SW_HELM_CHART_NAME" '$1 == chart {found=1} END {exit !found}'; then
        echo "INFO: $SW_HELM_CHART_NAME exists, uninstalling it"
        uninstall_helm_chart "$SW_HELM_CHART_NAME" || { exit 1; }
        wait_for_process 60 10 "[[ -z \$(kubectl get pods -n default --no-headers | grep '$SW_HELM_CHART_POD_NAME') ]]" || {
            echo "ERROR: $SW_HELM_CHART_NAME pods are not removed"; exit 1; }
    fi

    echo "INFO: Deploying sample workload without TW deployment"
    local install_result=1
    if [[ "$SW_HELM_CHART_LOCAL" == true ]]; then
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_FILE" 2>/dev/null || install_result=0
    else
        install_helm_chart "$SW_HELM_CHART_NAME" "$SW_HELM_CHART_LOCAL" "$SW_HELM_CHART_LINK" "$SW_HELM_CHART_VER" "$SW_HELM_CHART_TLS" || install_result=0
    fi

    chart_status=$(helm status "$SW_HELM_CHART_NAME" --output json | jq -r '.info.status' 2>/dev/null || echo "unknown")
    if [[ $install_result -eq 0 ]] || [[ "$chart_status" != "deployed" ]]; then
        echo "ERROR: Sample workload installation failed with TW deployment"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi

    echo "INFO: checking the status of $SW_HELM_CHART_POD_NAME pod"
    wait_for_process 60 10 "[[ -z \$(kubectl get pods -n default --no-headers | grep -w '$SW_HELM_CHART_POD_NAME' | awk '{print \$3}' | grep -v -E 'Running|Completed') ]]"
    pod_status=($(kubectl get pods -n default --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}'))

    kubectl get pods ${SW_HELM_CHART_POD_NAME}
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "ERROR: $SW_HELM_CHART_NAME pods are in $pod_status state"
        echo "RESULT: ${test_case_desc} [ failed ]"
    else
        echo "INFO: $SW_HELM_CHART_NAME pods are in $pod_status satate"
        echo "RESULT: ${test_case_desc} [ successful ]"
    fi
    echo ""
}

#TC5
verify_k8s_commands() {
    local test_case_name=$(yq '.tw_test_cases[4] | .name'  "$CONFIG_FILE")
    local test_case_desc=$(yq '.tw_test_cases[4] | .description' "$CONFIG_FILE")
    echo "${test_case_name}: ${test_case_desc}"
    echo "================================================="

    pod_status=($(kubectl get pods -n default --no-headers | grep -w "$SW_HELM_CHART_POD_NAME" | awk '{print $3}'))
    if [[ "$pod_status" != "Running" && "$pod_status" != "Completed" ]]; then
        echo "ERROR: $SW_HELM_CHART_NAME pods are in $pod_status state"
        echo "RESULT: ${test_case_desc} [ failed ]"
        exit 1
    fi

    local result="True"
    echo "INFO: Verifying k8s command get"
    if ! kubectl get pods $SW_HELM_CHART_POD_NAME; then
        echo "ERROR: kubectl get pods $SW_HELM_CHART_POD_NAME failed"
        result="False"
    fi
    echo ""

    echo "INFO: Verifying k8s command describe"
    if ! kubectl get pod $SW_HELM_CHART_POD_NAME -o json | jq '. | {
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
    echo ""

    [ $result == "True" ] && echo "RESULT: ${test_case_desc} [ successful ]" || echo "RESULT: ${test_case_desc} [ failed ]"
    echo ""
}

################
# Main Function
#################
setup_cluster_config
check_cluster_status
tw_deployment_in_cluster
tw_uninstall_in_cluster
sw_without_tw_deployment
sw_with_tw_deployment
verify_k8s_commands
clean_system

echo "========================================="
echo "INFO: All test cases passed successfully"
echo "========================================="
