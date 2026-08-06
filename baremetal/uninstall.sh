#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Trusted Compute Uninstallation Script
# This script uninstalls trusted-compute components from k8s/K3s/Docker
# Must be run as sudo

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load common functions and variables from install.sh
[[ -f "$SCRIPT_DIR/install.sh" ]] || { echo "[ERROR] install.sh not found in $SCRIPT_DIR" >&2; exit 1; }
source "$SCRIPT_DIR/install.sh" --source-only

# Function to remove the manifest
remove_tc_manifest() {
    print_status "Removing trusted-compute manifest from $K3S_MANIFESTS_DIR..."
    if [[ -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" ]]; then
        rm -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" \
            && print_status "Removed trusted-compute.yaml" \
            || { print_warning "Failed to remove trusted-compute.yaml"; }
    else
        print_warning "Manifest not found, skipping: $K3S_MANIFESTS_DIR/trusted-compute.yaml"
    fi
}

# Function to wait for a Kubernetes resource to be deleted
# Usage: wait_for_resource_deleted <resource_type> <resource_name> <namespace> <max_wait_seconds> <check_interval>
wait_for_resource_deleted() {
    local resource_type="$1"
    local resource_name="$2"
    local namespace="$3"
    local max_wait="${4:-60}"
    local check_interval="${5:-3}"

    local elapsed=0
    local namespace_flag=""
    [[ -n "$namespace" ]] && namespace_flag="-n $namespace"

    while kubectl get "$resource_type" "$resource_name" $namespace_flag &>/dev/null && [[ $elapsed -lt $max_wait ]]; do
        sleep "$check_interval"
        elapsed=$((elapsed + check_interval))
        if [[ $((elapsed % 15)) -eq 0 ]]; then
            print_status "Waiting for $resource_type '$resource_name' to be removed... (${elapsed}s)"
        fi
    done

    if kubectl get "$resource_type" "$resource_name" $namespace_flag &>/dev/null; then
        print_warning "$resource_type '$resource_name' still exists after ${max_wait}s, continuing..."
        return 1
    else
        print_status "$resource_type '$resource_name' fully removed"
        return 0
    fi
}

# Function to delete Kubernetes resources explicitly
delete_tc_k8s_resources() {
    print_status "Deleting Kubernetes resources explicitly..."

    # Delete AddOn resource
    if kubectl get addon trusted-compute -n kube-system &>/dev/null; then
        kubectl delete addon trusted-compute -n kube-system --timeout=60s \
            && print_status "Deleted AddOn: trusted-compute" \
            || print_warning "Failed to delete AddOn: trusted-compute"
        wait_for_resource_deleted "addon" "trusted-compute" "kube-system" 60 3
    else
        print_warning "AddOn 'trusted-compute' not found, skipping"
    fi

    # Delete HelmChart resources
    for chart in kata-deploy attestation-verifier trusted-workload; do
        if kubectl get helmchart "$chart" -n kube-system &>/dev/null; then
            local timeout=60
            [[ "$chart" == "attestation-verifier" ]] && timeout=120
            kubectl delete helmchart "$chart" -n kube-system --timeout=${timeout}s \
                && print_status "Deleted HelmChart: $chart" \
                || print_warning "Failed to delete HelmChart: $chart"
            wait_for_resource_deleted "helmchart" "$chart" "kube-system" "$timeout" 3
        else
            print_warning "HelmChart '$chart' not found, skipping"
        fi
    done

    # Delete namespaces
    for ns in trusted-compute kata-deploy; do
        if kubectl get namespace "$ns" &>/dev/null; then
            kubectl delete namespace "$ns" --timeout=60s \
                && print_status "Deleted namespace: $ns" \
                || print_warning "Failed to delete namespace: $ns"
            wait_for_resource_deleted "namespace" "$ns" "" 120 5
        else
            print_warning "Namespace '$ns' not found, skipping"
        fi
    done
}

# Function to remove Helm charts
remove_tc_charts() {
    print_status "Removing Helm charts from $K3S_CHARTS_DIR..."
    for chart in attestation-verifier trusted-workload kata-deploy; do
        if rm -f "$K3S_CHARTS_DIR/${chart}"*.tgz 2>/dev/null; then
            print_status "Removed ${chart} chart(s)"
        else
            print_warning "No ${chart} chart found to remove"
        fi
    done
}

# Function to remove container images
remove_tc_images() {
    print_status "Removing container images from $K3S_IMAGES_DIR..."
    for img in attestation-manager attestation-verifier kata-deploy; do
        local found
        found=$(find "$K3S_IMAGES_DIR" -maxdepth 1 -name "*${img}*.tar" 2>/dev/null)
        if [[ -n "$found" ]]; then
            echo "$found" | xargs rm -f
            print_status "Removed image tar(s) matching: ${img}"
        else
            print_warning "No image tar found matching: ${img}, skipping"
        fi
    done
}

# Function to remove containerd config
remove_tc_containerd_config() {
    print_status "Removing containerd config template..."
    if [[ -f "$CONTAINERD_CONFIG_DEST" ]]; then
        rm -f "$CONTAINERD_CONFIG_DEST" \
            && print_status "Removed containerd config: $CONTAINERD_CONFIG_DEST" \
            || print_warning "Failed to remove containerd config"
    else
        print_warning "Containerd config not found, skipping: $CONTAINERD_CONFIG_DEST"
    fi
}

# Function to stop docker deploy container
stop_tc_docker_deploy() {
    local compose_file="$SCRIPT_DIR/docker/tw-docker-deploy.yaml"
    print_status "Stopping kata-deploy ..."
    if [[ ! -f "$compose_file" ]]; then
        print_warning "Compose file not found, skipping: $compose_file"
        return
    fi
    docker compose -f "$compose_file" down \
        && print_status "kata-deploy stopped and removed successfully" \
        || print_warning "Failed to stop kata-deploy via docker compose"
}

# Function to remove users/groups
remove_tc_users_groups() {
    print_status "Removing trusted compute users and groups..."
    if id -u tc-agent &>/dev/null; then
        userdel tc-agent && print_status "Removed tc-agent user" || print_warning "Failed to remove tc-agent user"
    else
        print_warning "tc-agent user not found, skipping"
    fi
    if id -u tc-ima &>/dev/null; then
        userdel tc-ima && print_status "Removed tc-ima user" || print_warning "Failed to remove tc-ima user"
    else
        print_warning "tc-ima user not found, skipping"
    fi
    if getent group bm-agents &>/dev/null; then
        groupdel bm-agents && print_status "Removed bm-agents group" || print_warning "Failed to remove bm-agents group"
    else
        print_warning "bm-agents group not found, skipping"
    fi
}

# Function to print uninstall summary (K3s)
print_tc_k3s_uninstall_summary() {
    print_status "Uninstallation completed."
    print_status "Summary of removed components (TC uninstallation for K3s):"
    echo "  - Manifest removed from: $K3S_MANIFESTS_DIR"
    echo "  - K3s resources deleted: AddOn, HelmCharts Namespaces"
    echo "  - K3s service:           Restarted"
    echo "  - Charts removed from:   $K3S_CHARTS_DIR"
    echo "  - Images removed from:   $K3S_IMAGES_DIR"
    echo "  - Containerd config:     $CONTAINERD_CONFIG_DEST"
    echo "  - Users/groups removed:  tc-agent, tc-ima, bm-agents"
}

# Function to print uninstall summary (Docker)
print_tc_docker_uninstall_summary() {
    print_status "Uninstallation completed."
    print_status "Summary of removed components (TC uninstallation for Docker):"
    echo "  - kata-deploy container stopped and removed"
}

# Pre-flight check for K3s installation
check_tc_k3s_installed() {
    print_status "Checking if TC is installed for K3s..."
    local found=false
    [[ -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" ]] && found=true
    [[ -n "$(ls "$K3S_CHARTS_DIR"/attestation-verifier*.tgz "$K3S_CHARTS_DIR"/kata-deploy*.tgz 2>/dev/null)" ]] && found=true
    command -v kubectl &>/dev/null && kubectl get namespace trusted-compute &>/dev/null && found=true
    if [[ "$found" == false ]]; then
        print_error "TC K3s installation not detected (manifest, charts, and namespace not found). Nothing to uninstall."
        exit 1
    fi
    print_status "TC K3s installation detected."
}

# Pre-flight check for Docker installation
check_tc_docker_installed() {
    print_status "Checking if TC is installed for Docker..."
    if ! command -v docker &>/dev/null; then
        print_error "docker is not installed or not in PATH"
        exit 1
    fi
    if ! docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^kata-deploy$'; then
        print_error "kata-deploy container not found. TC Docker installation not detected. Nothing to uninstall."
        exit 1
    fi
    print_status "kata-deploy container detected."
}

# Pre-flight check for K8s installation
check_tc_k8s_installed() {
    print_status "Checking if TC is installed for K8s..."
    if ! command -v kubectl &>/dev/null; then
        print_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    if ! command -v helm &>/dev/null; then
        print_error "helm is not installed or not in PATH"
        exit 1
    fi
    local found=false
    kubectl get namespace trusted-compute &>/dev/null 2>&1 && found=true
    helm list -n trusted-compute 2>/dev/null | grep -q attestation-verifier && found=true
    helm list -n kata-deploy 2>/dev/null | grep -q kata-deploy && found=true
    if [[ "$found" == false ]]; then
        print_error "TC K8s installation not detected (namespaces and helm releases not found). Nothing to uninstall."
        exit 1
    fi
    print_status "TC K8s installation detected."
}

# Function to uninstall Helm releases for K8s
uninstall_helm_releases() {
    print_status "Uninstalling Helm releases..."

    # Uninstall trusted-workload
    if helm list -n kata-deploy 2>/dev/null | grep -q trusted-workload; then
        print_status "Uninstalling trusted-workload..."
        helm uninstall trusted-workload -n kata-deploy --wait --timeout 5m \
            && print_status "trusted-workload uninstalled" \
            || print_warning "Failed to uninstall trusted-workload"
    else
        print_warning "Helm release 'trusted-workload' not found, skipping"
    fi

    # Uninstall kata-deploy
    if helm list -n kata-deploy 2>/dev/null | grep -q kata-deploy; then
        print_status "Uninstalling kata-deploy..."
        helm uninstall kata-deploy -n kata-deploy --wait --timeout 5m \
            && print_status "kata-deploy uninstalled" \
            || print_warning "Failed to uninstall kata-deploy"
    else
        print_warning "Helm release 'kata-deploy' not found, skipping"
    fi

    # Uninstall attestation-verifier
    if helm list -n trusted-compute 2>/dev/null | grep -q attestation-verifier; then
        print_status "Uninstalling attestation-verifier..."
        helm uninstall attestation-verifier -n trusted-compute --wait --timeout 10m \
            && print_status "attestation-verifier uninstalled" \
            || print_warning "Failed to uninstall attestation-verifier"
    else
        print_warning "Helm release 'attestation-verifier' not found, skipping"
    fi
}

# Function to delete namespaces for K8s
delete_k8s_namespaces() {
    print_status "Deleting namespaces..."

    for ns in trusted-compute kata-deploy; do
        if kubectl get namespace "$ns" &>/dev/null; then
            print_status "Deleting namespace: $ns"
            kubectl delete namespace "$ns" --timeout=120s \
                && print_status "Deleted namespace: $ns" \
                || print_warning "Failed to delete namespace: $ns"
            wait_for_resource_deleted "namespace" "$ns" "" 120 5
        else
            print_warning "Namespace '$ns' not found, skipping"
        fi
    done
}

# Function to remove images from containerd (K8s)
remove_k8s_containerd_images() {
    print_status "Removing container images from containerd..."

    if ! command -v ctr &>/dev/null; then
        print_warning "ctr command not found, skipping image removal"
        return
    fi

    # List of image patterns to remove
    local patterns=("attestation-manager" "attestation-verifier" "kata-deploy")

    for pattern in "${patterns[@]}"; do
        local images
        images=$(ctr -n k8s.io images list | grep -i "$pattern" | awk '{print $1}' || true)
        if [[ -n "$images" ]]; then
            echo "$images" | while read -r img; do
                print_status "Removing image: $img"
                ctr -n k8s.io images remove "$img" \
                    && print_status "Removed: $img" \
                    || print_warning "Failed to remove: $img"
            done
        else
            print_warning "No images found matching pattern: $pattern"
        fi
    done
}

# Function to restore containerd config for K8s
restore_containerd_config_k8s() {
    print_status "Restoring containerd configuration..."

    # Remove the kata-qemu drop-in we added
    if [[ -f "$K8S_CONTAINERD_DIR/conf.d/kata-qemu.toml" ]]; then
        rm -f "$K8S_CONTAINERD_DIR/conf.d/kata-qemu.toml" \
            && print_status "Removed kata-qemu.toml drop-in" \
            || print_warning "Failed to remove kata-qemu.toml drop-in"
    else
        print_warning "kata-qemu.toml drop-in not found, skipping"
    fi

    # Undo the conf.d imports edit made to config.toml during install
    local config_backup="${K8S_CONTAINERD_CONFIG}.tc-orig"
    local config_generated_marker="${K8S_CONTAINERD_DIR}/.tc-config-generated"
    if [[ -f "$config_generated_marker" ]]; then
        rm -f "$K8S_CONTAINERD_DIR/config.toml" "$config_generated_marker" \
            && print_status "Removed containerd config.toml generated by installer" \
            || print_warning "Failed to remove generated config.toml"
    elif [[ -f "$config_backup" ]]; then
        mv "$config_backup" "$K8S_CONTAINERD_CONFIG" \
            && print_status "Restored original containerd config.toml (removed conf.d imports)" \
            || print_warning "Failed to restore original config.toml from backup"
    else
        print_warning "No containerd config.toml backup found; conf.d imports line may still be present in $K8S_CONTAINERD_CONFIG"
    fi

    # Restart containerd
    print_status "Restarting containerd service..."
    systemctl restart containerd \
        && print_status "Containerd restarted successfully" \
        || print_warning "Failed to restart containerd"
    sleep 5
}

# Function to print uninstall summary (K8s)
print_tc_k8s_uninstall_summary() {
    print_status "Uninstallation completed."
    print_status "Summary of removed components (TC uninstallation for K8s):"
    echo "  - Helm releases:         attestation-verifier, kata-deploy, trusted-workload"
    echo "  - Namespaces deleted:    trusted-compute, kata-deploy"
    echo "  - Images removed from:   containerd (k8s.io namespace)"
    echo "  - Containerd config:     kata-qemu.toml drop-in removed"
    echo "  - Users/groups removed:  tc-agent, tc-ima, bm-agents"
}

uninstall_tc_k8s() {
    check_tc_k8s_installed
    print_status "Starting TC uninstallation for K8s..."
    uninstall_helm_releases
    delete_k8s_namespaces
    remove_k8s_containerd_images
    restore_containerd_config_k8s
    remove_tc_users_groups
    rm -rf "$SCRIPT_DIR/k8s"
    print_tc_k8s_uninstall_summary
}

uninstall_tc_k3s() {
    check_tc_k3s_installed
    print_status "Starting TC uninstallation for K3s..."
    remove_tc_manifest
    delete_tc_k8s_resources
    remove_tc_charts
    remove_tc_images
    remove_tc_containerd_config
    remove_tc_users_groups
    restart_k3s
    print_tc_k3s_uninstall_summary
}

uninstall_tc_docker() {
    check_tc_docker_installed
    print_status "Starting TC uninstallation for Docker..."
    stop_tc_docker_deploy
    print_tc_docker_uninstall_summary
}

# Interactive option selector for uninstall
select_uninstall_option() {
    local options=("K3s    - TC uninstallation for K3s" "K8s    - TC uninstallation for K8s" "Docker - TC uninstallation for Docker")
    local selected=0 key k2 k3
    local -a modes=(k3s k8s docker)

    _draw_menu() {
        printf '\nSelect uninstallation option (use arrow keys, press Enter to confirm):\n\n'
        for i in "${!options[@]}"; do
            [[ $i -eq $selected ]] \
                && printf "  \e[7m ${options[$i]} \e[0m\n" \
                || printf "    ${options[$i]}\n"
        done
    }

    tput civis; _draw_menu
    while IFS= read -rsn1 key; do
        [[ $key == $'\x1b' ]] && { IFS= read -rsn1 -t 0.1 k2; IFS= read -rsn1 -t 0.1 k3; key+="${k2}${k3}"; }
        case "$key" in
            $'\x1b[A'|$'\x1b[D') (( selected-- )) || true; (( selected < 0 )) && selected=$(( ${#options[@]} - 1 )) ;;
            $'\x1b[B'|$'\x1b[C') (( selected++ )) || true; (( selected >= ${#options[@]} )) && selected=0 ;;
            '') break ;;
        esac
        tput cuu $(( ${#options[@]} + 3 )); _draw_menu
    done
    tput cnorm; printf '\n'
    DEPLOYMENT_OPTION="${modes[$selected]}"
}

# Main script execution
main() {
    set_paths
    DEPLOYMENT_OPTION=""

    # Parse argument (reuse same flags as install.sh)
    case "${1:-}" in
        --k3s)    DEPLOYMENT_OPTION="k3s" ;;
        --k8s)    DEPLOYMENT_OPTION="k8s" ;;
        --docker) DEPLOYMENT_OPTION="docker" ;;
        "")       : ;;
        *)
            print_error "Unknown argument: $1"
            echo "Usage: $0 [--k3s | --k8s | --docker]"
            exit 1
            ;;
    esac

    check_root
    [[ -z "$DEPLOYMENT_OPTION" ]] && select_uninstall_option

    case "$DEPLOYMENT_OPTION" in
        k3s)    uninstall_tc_k3s ;;
        k8s)    uninstall_tc_k8s ;;
        docker) uninstall_tc_docker ;;
    esac
}

main "$@"
