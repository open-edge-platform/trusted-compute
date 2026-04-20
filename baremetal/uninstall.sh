#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Trusted Compute Uninstallation Script
# This script uninstalls trusted-compute components from K3s/Docker
# Must be run as sudo

set -e  # Exit on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load common functions and variables from install.sh
[[ -f "$SCRIPT_DIR/install.sh" ]] || { echo "[ERROR] install.sh not found in $SCRIPT_DIR" >&2; exit 1; }
source "$SCRIPT_DIR/install.sh" --source-only

# Function to remove the manifest (triggers K3s to uninstall HelmCharts)
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

# Function to wait for namespaces to be cleaned up
wait_for_namespace_deleted() {
    local ns="$1"
    local timeout="$2"
    print_status "Waiting for namespace '$ns' to be deleted (timeout: ${timeout}s)..."
    local elapsed=0
    while kubectl get namespace "$ns" &>/dev/null; do
        if [[ $elapsed -ge $timeout ]]; then
            print_warning "Timeout: namespace '$ns' was not deleted after ${timeout} seconds. Continuing..."
            return
        fi
        sleep 15
        elapsed=$((elapsed + 15))
    done
    print_status "Namespace '$ns' has been deleted."
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
    for img in attestation-manager attestation-verifier kata-deploy trusted-workload; do
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
    echo "  - Charts removed from:   $K3S_CHARTS_DIR"
    echo "  - Images removed from:   $K3S_IMAGES_DIR"
    echo "  - Containerd config:     $CONTAINERD_CONFIG_DEST"
    echo "  - Users/groups:          tc-agent, tc-ima, bm-agents"
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
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^kata-deploy$'; then
        print_error "kata-deploy container is not running. TC Docker installation not detected. Nothing to uninstall."
        exit 1
    fi
    print_status "kata-deploy container is running."
}

uninstall_tc_k3s() {
    check_tc_k3s_installed
    print_status "Starting TC uninstallation for K3s..."
    remove_tc_manifest
    restart_k3s
    print_status "Waiting for HelmChart resources to be cleaned up..."
    wait_for_namespace_deleted "trusted-compute" "$TIMEOUT"
    wait_for_namespace_deleted "kata-deploy" "$TIMEOUT"
    remove_tc_charts
    remove_tc_images
    remove_tc_containerd_config
    remove_tc_users_groups
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
    local options=("K3s    - TC uninstallation for K3s" "Docker - TC uninstallation for Docker")
    local selected=0 key k2 k3
    local -a modes=(k3s docker)

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
    TIMEOUT=$((10*60))
    DEPLOYMENT_OPTION=""

    # Parse argument (reuse same flags as install.sh)
    case "${1:-}" in
        --k3s)    DEPLOYMENT_OPTION="k3s" ;;
        --docker) DEPLOYMENT_OPTION="docker" ;;
        "")       : ;;
        *)
            print_error "Unknown argument: $1"
            echo "Usage: $0 [--k3s | --docker]"
            exit 1
            ;;
    esac

    check_root
    [[ -z "$DEPLOYMENT_OPTION" ]] && select_uninstall_option

    case "$DEPLOYMENT_OPTION" in
        k3s)    uninstall_tc_k3s ;;
        docker) uninstall_tc_docker ;;
    esac
}

main "$@"
