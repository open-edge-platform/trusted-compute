#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

# Trusted Compute Installation Script
# This script installs trusted-compute components for K3s
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

# Function to check required directories/files
check_requirements() {
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

# Function to print summary
print_summary() {
    print_status "Installation completed successfully!"
    print_status "Summary of installed components:"
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

# Main script execution
main() {
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    K3S_CHARTS_DIR="/var/lib/rancher/k3s/server/static/charts"
    K3S_MANIFESTS_DIR="/var/lib/rancher/k3s/server/manifests"
    K3S_IMAGES_DIR="/var/lib/rancher/k3s/agent/images"
    CONTAINERD_ETC_DIR="/var/lib/rancher/k3s/agent/etc/containerd"
    CONTAINERD_CONFIG_SRC="$SCRIPT_DIR/containerd/config-v3.toml.tmpl"
    CONTAINERD_CONFIG_DEST="$CONTAINERD_ETC_DIR/config-v3.toml.tmpl"
    TIMEOUT=$((20*60))
    INTERVAL=15

    check_root
    check_secure_boot
    print_status "Installation script running from: $SCRIPT_DIR"
    check_requirements
    print_status "Starting trusted-compute installation..."
    create_target_dirs
    copy_charts
    copy_manifests
    copy_images
    copy_containerd_config
    set_permissions
    create_users_groups
    restart_k3s
    print_summary
    print_status "Wait for daemonsets and deployments to become ready..."
    sleep 180
    wait_for_namespace_ready "confidential-containers-system" "$TIMEOUT"
    wait_for_namespace_ready "trusted-compute" "$TIMEOUT"
}

main
