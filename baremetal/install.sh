#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Trusted Compute Installation Script
# Supports two installation options:
#   --k3s     Install trusted-compute components for K3s
#   --docker  Install Trusted-compute components for Docker
# Must be run as sudo

set -e  # Exit on any error

# Color codes for output
RED='\e[0;31m'
GREEN='\e[0;32m'
YELLOW='\e[1;33m'
NC='\e[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}


# Function to check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Shared path constants (call after SCRIPT_DIR is set)
set_paths() {
    K3S_CHARTS_DIR="/var/lib/rancher/k3s/server/static/charts"
    K3S_MANIFESTS_DIR="/var/lib/rancher/k3s/server/manifests"
    K3S_IMAGES_DIR="/var/lib/rancher/k3s/agent/images"
    CONTAINERD_ETC_DIR="/var/lib/rancher/k3s/agent/etc/containerd"
    CONTAINERD_CONFIG_SRC="$SCRIPT_DIR/containerd/config-v3.toml.tmpl"
    CONTAINERD_CONFIG_DEST="$CONTAINERD_ETC_DIR/config-v3.toml.tmpl"
}

# Function to check required directories/files for TC installation for K3s
check_tc_requirements_k3s() {
    if [[ ! -d "$SCRIPT_DIR/charts" ]]; then
        print_error "Charts directory not found: $SCRIPT_DIR/charts"
        exit 1
    fi
    if [[ ! -d "$SCRIPT_DIR/manifests" ]]; then
        print_error "Manifests directory not found: $SCRIPT_DIR/manifests"
        exit 1
    fi
    if [[ ! -d "$SCRIPT_DIR/images" ]]; then
        print_error "Images directory not found: $SCRIPT_DIR/images"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_DIR/manifests/trusted-compute.yaml" ]]; then
        print_error "trusted-compute.yaml not found in manifests directory"
        exit 1
    fi
}

# Function to create target directories
create_target_dirs() {
    print_status "Creating target directories if they don't exist..."
    [[ ! -d "$K3S_CHARTS_DIR" ]] && mkdir -p "$K3S_CHARTS_DIR" && print_status "Created charts directory: $K3S_CHARTS_DIR" || print_status "Charts directory already exists: $K3S_CHARTS_DIR"
    [[ ! -d "$K3S_MANIFESTS_DIR" ]] && mkdir -p "$K3S_MANIFESTS_DIR" && print_status "Created manifests directory: $K3S_MANIFESTS_DIR" || print_status "Manifests directory already exists: $K3S_MANIFESTS_DIR"
    [[ ! -d "$K3S_IMAGES_DIR" ]] && mkdir -p "$K3S_IMAGES_DIR" && print_status "Created images directory: $K3S_IMAGES_DIR" || print_status "Images directory already exists: $K3S_IMAGES_DIR"
}

# Function to copy charts
copy_charts() {
    print_status "Copying Helm charts to $K3S_CHARTS_DIR..."
    cp -v "$SCRIPT_DIR/charts"/*.tgz "$K3S_CHARTS_DIR/" && print_status "Successfully copied charts" || { print_error "Failed to copy charts"; exit 1; }
}

# Function to copy manifests
copy_manifests() {
    print_status "Copying manifest to $K3S_MANIFESTS_DIR..."
    cp -v "$SCRIPT_DIR/manifests/trusted-compute.yaml" "$K3S_MANIFESTS_DIR/" && print_status "Successfully copied trusted-compute.yaml" || { print_error "Failed to copy trusted-compute.yaml"; exit 1; }
}

# Function to copy images
copy_images() {
    print_status "Copying container images to $K3S_IMAGES_DIR..."
    cp -v "$SCRIPT_DIR/images"/*.tar "$K3S_IMAGES_DIR/" && print_status "Successfully copied container images" || { print_error "Failed to copy container images"; exit 1; }
}

# Function to check Ubuntu Secure Boot status
check_secure_boot() {
    print_status "Checking Secure Boot status..."
    if mokutil --sb-state &>/dev/null; then
        local sb_state=$(mokutil --sb-state | grep -i 'SecureBoot' | awk '{print $2}')
        if [[ "$sb_state" == "enabled" ]]; then
            print_status "Secure Boot is ENABLED."
        else
            print_warning "Secure Boot is DISABLED."
            exit 1
        fi
    else
        print_warning "mokutil not found or Secure Boot status cannot be determined."
        exit 1
    fi
}

# Function to copy containerd config template
copy_containerd_config() {
    print_status "Copying containerd config template..."
    [[ ! -d "$CONTAINERD_ETC_DIR" ]] && mkdir -p "$CONTAINERD_ETC_DIR" && print_status "Created containerd etc directory: $CONTAINERD_ETC_DIR"
    if [[ -f "$CONTAINERD_CONFIG_SRC" ]]; then
        cp -v "$CONTAINERD_CONFIG_SRC" "$CONTAINERD_CONFIG_DEST" && print_status "Successfully copied containerd config template" || { print_error "Failed to copy containerd config template"; exit 1; }
    else
        print_error "containerd config template not found: $CONTAINERD_CONFIG_SRC"
        exit 1
    fi
}

# Function to set permissions
set_permissions() {
    print_status "Setting proper permissions..."
    chown -R root:root "$K3S_CHARTS_DIR"
    chown -R root:root "$K3S_MANIFESTS_DIR"
    chown -R root:root "$K3S_IMAGES_DIR"
    chmod -R 644 "$K3S_CHARTS_DIR"/*.tgz
    chmod -R 644 "$K3S_MANIFESTS_DIR"/trusted-compute.yaml
    chmod -R 644 "$K3S_IMAGES_DIR"/*.tar
}

# Function to create users/groups
create_users_groups() {
    print_status "Creating trusted compute users and groups..."
    groupadd -f bm-agents -g 500 --system && print_status "Successfully created/verified bm-agents group" || print_warning "bm-agents group may already exist"
    id -u tc-agent &>/dev/null || useradd tc-agent -u 503 --system -g bm-agents -s /sbin/nologin && print_status "Successfully created tc-agent user" || print_status "tc-agent user already exists"
    id -u tc-ima &>/dev/null || useradd tc-ima -u 504 --system -g bm-agents -s /sbin/nologin && print_status "Successfully created tc-ima user" || print_status "tc-ima user already exists"
}

# Function to restart K3s
restart_k3s() {
    print_status "Restarting K3s service to apply changes..."
    systemctl restart k3s && print_status "Successfully restarted K3s service" || { print_error "Failed to restart K3s service"; exit 1; }
}

# Function to check K3s service is installed and enabled
check_k3s_service() {
    command -v k3s &>/dev/null || { print_error "k3s is not installed or not in PATH"; exit 1; }
    systemctl is-enabled k3s &>/dev/null || { print_error "k3s service is not enabled. Please install K3s first."; exit 1; }
    print_status "K3s service is available."
}

# Function to print summary (TC installation for K3s)
print_tc_k3s_summary() {
    print_status "Installation completed successfully!"
    print_status "Summary of installed components (TC installation for K3s):"
    echo "  - Charts copied to: $K3S_CHARTS_DIR"
    echo "  - Manifest copied to: $K3S_MANIFESTS_DIR/trusted-compute.yaml"
    echo "  - Images copied to: $K3S_IMAGES_DIR"
    echo "  - Users and groups: bm-agents group, tc-agent user, tc-ima user"
}


# Function to wait for a namespace's resources using kubectl rollout status
wait_for_namespace_ready() {
    local ns="$1"
    local timeout="$2"
    print_status "Waiting for daemonsets and deployments in namespace '$ns' to become ready (timeout: $timeout seconds)..."
    local success=true
    if ! kubectl rollout status daemonset,deployment -n "$ns" --timeout=${timeout}s; then
        print_error "Some DaemonSets or Deployments did not become ready in time."
        success=false
    fi
    if [[ "$success" == true ]]; then
        print_status "All daemonsets and deployments in namespace '$ns' are ready."
    else
        print_error "Timeout: Some resources in namespace '$ns' are not ready after $timeout seconds."
        print_error "Check with 'kubectl get daemonset -n $ns' and 'kubectl get deployment -n $ns'."
        exit 1
    fi
}

# Function to check requirements for TC installation for Docker
check_tc_requirements_docker() {
    if [[ ! -d "$SCRIPT_DIR/images" ]]; then
        print_error "Images directory not found: $SCRIPT_DIR/images"
        exit 1
    fi
    if [[ ! -f "$SCRIPT_DIR/docker/tw-docker-deploy.yaml" ]]; then
        print_error "tw-docker-deploy.yaml not found: $SCRIPT_DIR/docker/tw-docker-deploy.yaml"
        exit 1
    fi
    if ! command -v docker &>/dev/null; then
        print_error "docker is not installed or not in PATH"
        exit 1
    fi
    if ! docker compose version &>/dev/null; then
        print_error "docker compose plugin is not installed or not available"
        exit 1
    fi
}

# Function to import the kata-deploy image
import_kata_deploy_image() {
    print_status "Importing kata-deploy container image..."
    local tar_file
    tar_file=$(find "$SCRIPT_DIR/images" -maxdepth 1 -name "*kata-deploy*.tar" | head -n 1)
    if [[ -z "$tar_file" ]]; then
        print_error "No kata-deploy image tar found in $SCRIPT_DIR/images"
        exit 1
    fi
    print_status "Loading image from: $tar_file"
    docker load -i "$tar_file" && print_status "Successfully loaded kata-deploy image" || { print_error "Failed to load kata-deploy image"; exit 1; }
}

# Function to start the docker compose service
start_docker_deploy() {
    print_status "Starting kata-deploy via Docker Compose..."
    docker compose -f "$SCRIPT_DIR/docker/tw-docker-deploy.yaml" up -d \
        && print_status "kata-deploy container started successfully" \
        || { print_error "Failed to start kata-deploy container"; exit 1; }
}

# Function to print summary (TC installation for Docker)
print_tc_docker_summary() {
    print_status "Installation completed successfully!"
    print_status "Summary of installed components (TC installation for Docker):"
    echo "  - kata-deploy image loaded from: $SCRIPT_DIR/images"
    echo "  - Docker Compose file:           $SCRIPT_DIR/docker/tw-docker-deploy.yaml"
    echo "  - Container started:             kata-deploy"
}

# Check if Docker TC installation already exists (blocks K3s install)
check_no_tc_docker_conflict() {
    if command -v docker &>/dev/null && docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^kata-deploy$'; then
        print_error "TC Docker installation is already active."
        print_error "Please uninstall it first: sudo ./uninstall.sh --docker  (or run sudo ./uninstall.sh and select Docker)"
        exit 1
    fi
}

# Check if K3s TC installation already exists (blocks Docker install)
check_no_tc_k3s_conflict() {
    local found=false
    [[ -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" ]] && found=true
    command -v kubectl &>/dev/null && kubectl get namespace trusted-compute &>/dev/null 2>&1 && found=true
    if [[ "$found" == true ]]; then
        print_error "TC K3s installation is already active."
        print_error "Please uninstall it first: sudo ./uninstall.sh --k3s  (or run sudo ./uninstall.sh and select K3s)"
        exit 1
    fi
}

install_tc_k3s() {
    check_no_tc_docker_conflict
    check_secure_boot
    check_k3s_service
    print_status "Installation script running from: $SCRIPT_DIR"
    check_tc_requirements_k3s
    print_status "Starting TC installation for K3s..."
    create_target_dirs
    copy_charts
    copy_manifests
    copy_images
    copy_containerd_config
    set_permissions
    create_users_groups
    restart_k3s
    print_tc_k3s_summary
    print_status "Wait for daemonsets and deployments to become ready..."
    sleep 180
    wait_for_namespace_ready "confidential-containers-system" "$TIMEOUT"
    wait_for_namespace_ready "trusted-compute" "$TIMEOUT"
}

install_tc_docker() {
    check_no_tc_k3s_conflict
    check_secure_boot
    print_status "Installation script running from: $SCRIPT_DIR"
    check_tc_requirements_docker
    print_status "Starting TC installation for Docker..."
    import_kata_deploy_image
    start_docker_deploy
    print_tc_docker_summary
}

# interactive menu

select_deployment_option() {
    local options=("K3s    - TC installation for K3s" "Docker - TC installation for Docker")
    local selected=0 key k2 k3
    local -a modes=(k3s docker)

    _draw_menu() {
        printf '\nSelect installation option (use arrow keys, press Enter to confirm):\n\n'
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
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    set_paths
    TIMEOUT=$((20*60))
    DEPLOYMENT_OPTION=""

    # Parse argument
    case "${1:-}" in
        --k3s)    DEPLOYMENT_OPTION="k3s" ;;
        --docker) DEPLOYMENT_OPTION="docker" ;;
        "")       : ;;  # will prompt below
        *)
            print_error "Unknown argument: $1"
            echo "Usage: $0 [--k3s | --docker]"
            exit 1
            ;;
    esac

    check_root

    # If no option given, show interactive menu
    [[ -z "$DEPLOYMENT_OPTION" ]] && select_deployment_option

    case "$DEPLOYMENT_OPTION" in
        k3s)    install_tc_k3s ;;
        docker) install_tc_docker ;;
    esac
}

[[ "${1:-}" == "--source-only" ]] && return 0
main "$@"
