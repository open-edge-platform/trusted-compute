#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Trusted Compute Installation Script
# Supports three installation options:
#   --k3s     Install trusted-compute components for K3s
#   --k8s     Install trusted-compute components for K8s
#   --docker  Install Trusted-compute components for Docker
# Must be run as sudo

set -e  # Exit on any error

# Injected at package build time by Makefile
ATTESTATION_MANAGER_VERSION=""
KATA_DEPLOY_VERSION=""

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

    # K8s specific paths
    K8S_CONTAINERD_DIR="/etc/containerd"
    K8S_CONTAINERD_CONFIG="$K8S_CONTAINERD_DIR/config.toml"
}

# Function to check required directories/files for TC installation.
# Accepts "k3s" or "k8s" as mode; yq is only required for k8s installs.
check_tc_requirements() {
    local mode="$1"
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
    if [[ ! -f "$CONTAINERD_CONFIG_SRC" ]]; then
        print_error "containerd config template not found: $CONTAINERD_CONFIG_SRC"
        exit 1
    fi
    if [[ "$mode" == "k8s" ]]; then
        check_yq_command
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

# Function to restart containerd
restart_containerd() {
    print_status "Restarting containerd service..."
    systemctl restart containerd && print_status "Containerd restarted successfully" || { print_error "Failed to restart containerd"; exit 1; }
    sleep 5
}

# Function to setup kubeconfig for sudo user
setup_kubeconfig() {
    local admin_kubeconfig="/etc/kubernetes/admin.conf"
    local root_home=$(getent passwd root | cut -d: -f6)
    local root_kubeconfig="${root_home}/.kube/config"

    if [[ -f "$admin_kubeconfig" ]]; then
        mkdir -p "${root_home}/.kube"
        if [[ -f "$root_kubeconfig" ]] && ! cmp -s "$admin_kubeconfig" "$root_kubeconfig"; then
            local backup_kubeconfig="${root_kubeconfig}.bak.$(date +%Y%m%d%H%M%S)"
            cp "$root_kubeconfig" "$backup_kubeconfig"
            print_warning "Existing kubeconfig differs from $admin_kubeconfig; backed up to $backup_kubeconfig"
        fi
        cp "$admin_kubeconfig" "$root_kubeconfig"
        chmod 600 "$root_kubeconfig"
    else
        print_warning "Kubeconfig not found at $admin_kubeconfig"
    fi
}

# Function to check K3s service is installed and enabled
check_k3s_service() {
    command -v k3s &>/dev/null || { print_error "k3s is not installed or not in PATH"; exit 1; }
    systemctl is-enabled k3s &>/dev/null || { print_error "k3s service is not enabled. Please install K3s first."; exit 1; }
    print_status "K3s service is available."
}

# Function to check yq is available
check_yq_command() {
    command -v yq &>/dev/null || {
        print_error "yq is not installed or not in PATH. Please install yq."
        exit 1
    }
}

# Function to check K8s cluster connectivity
check_k8s_cluster() {
    command -v kubectl &>/dev/null || { print_error "kubectl is not installed or not in PATH"; exit 1; }
    command -v helm &>/dev/null || { print_error "helm is not installed or not in PATH. Please install Helm first."; exit 1; }
    command -v containerd &>/dev/null || { print_error "containerd is not installed or not in PATH"; exit 1; }
    command -v ctr &>/dev/null || { print_error "ctr (containerd CLI) is not installed or not in PATH"; exit 1; }
    systemctl is-active kubelet &>/dev/null || { print_error "kubelet service is not active on node"; exit 1; }
    systemctl is-active containerd &>/dev/null || { print_error "containerd service is not active on node"; exit 1; }
    kubectl get nodes --request-timeout=5s &>/dev/null || { print_error "Cannot connect to K8s cluster."; exit 1; }
    print_status "K8s cluster is accessible."
}

# Function to check for a control-plane taint that blocks pod scheduling on single-node clusters
check_node_taints() {
    print_status "Checking nodes for scheduling-blocking taints..."
    local tainted_nodes
    tainted_nodes=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"|"}{range .spec.taints[*]}{.key}={.effect}{","}{end}{"\n"}{end}' \
        | grep 'node-role.kubernetes.io/control-plane=NoSchedule' | cut -d'|' -f1 || true)
    if [[ -n "$tainted_nodes" ]]; then
        print_warning "The following nodes have the 'node-role.kubernetes.io/control-plane:NoSchedule' taint, which prevents pods from being scheduled on this single-node cluster:"
        echo "$tainted_nodes"
        print_warning "Remove the taint and re-run the script, for example:"
        print_warning "  kubectl taint nodes --all node-role.kubernetes.io/control-plane-"
        exit 1
    fi
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

# Function to start the docker compose service and wait until kata-deploy finishes installing
start_docker_deploy() {
    print_status "Starting kata-deploy via Docker Compose..."
    docker compose -f "$SCRIPT_DIR/docker/tw-docker-deploy.yaml" up -d \
        && print_status "kata-deploy container started successfully" \
        || { print_error "Failed to start kata-deploy container"; exit 1; }

    local deadline=$(( $(date +%s) + 120 ))
    while true; do
        if docker logs kata-deploy 2>&1 | grep -q "Installation complete"; then
            return 0
        fi
        if [[ $(date +%s) -ge $deadline ]]; then
            print_error "Timed out waiting for kata-deploy to finish installation (120s)"
            docker logs kata-deploy 2>&1 || true
            exit 1
        fi
        sleep 5
    done
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
    if command -v docker &>/dev/null && docker container inspect kata-deploy &>/dev/null 2>&1; then
        print_error "TC Docker installation already exists (container 'kata-deploy' is present)."
        print_error "Please uninstall it first: sudo ./uninstall.sh --docker  (or run sudo ./uninstall.sh and select Docker)"
        exit 1
    fi
}

# Check if K3s TC installation already exists (blocks Docker install)
check_no_tc_k3s_conflict() {
    if [[ -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" ]]; then
        print_error "TC K3s installation is already active."
        print_error "Please uninstall it first: sudo ./uninstall.sh --k3s  (or run sudo ./uninstall.sh and select K3s)"
        exit 1
    fi
}

# Check if K8s TC installation already exists (blocks other installs)
check_no_tc_k8s_conflict() {
    if command -v kubectl &>/dev/null && kubectl get namespace trusted-compute &>/dev/null 2>&1; then
        # Check if it's not from k3s
        if [[ ! -f "$K3S_MANIFESTS_DIR/trusted-compute.yaml" ]]; then
            print_error "TC K8s installation is already active."
            print_error "Please uninstall it first: sudo ./uninstall.sh --k8s  (or run sudo ./uninstall.sh and select K8s)"
            exit 1
        fi
    fi
}

# Function to import images into containerd for K8s
import_images_to_containerd() {
    print_status "Importing container images to containerd..."
    local imported=0
    for img_tar in "$SCRIPT_DIR/images"/*.tar; do
        [[ -f "$img_tar" ]] || continue
        print_status "Loading image: $(basename "$img_tar")"
        if ctr -n k8s.io images import "$img_tar"; then
            print_status "Successfully imported: $(basename "$img_tar")"
            imported=$((imported + 1))
        else
            print_error "Failed to import: $(basename "$img_tar")"
            exit 1
        fi
    done
    if [[ $imported -eq 0 ]]; then
        print_error "No container image tarballs (*.tar) found in $SCRIPT_DIR/images"
        exit 1
    fi
    print_status "Imported $imported container images to containerd"
}

# Function to install Helm charts for K8s
install_helm_charts_k8s() {
    print_status "Installing Helm charts..."
    local tc_registry="registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute"
    # Create namespaces first
    kubectl create namespace trusted-compute --dry-run=client -o yaml | kubectl apply -f - && print_status "Namespace 'trusted-compute' ready"
    kubectl create namespace kata-deploy --dry-run=client -o yaml | kubectl apply -f - && print_status "Namespace 'kata-deploy' ready"

    # Install kata-deploy chart
    print_status "Installing kata-deploy chart..."
    # Derive values from the k3s manifest, patch for k8s
    local k8s_dir="$SCRIPT_DIR/k8s"
    mkdir -p "$k8s_dir"
    # Extract yq's own exit status separately from sed's so a yq failure isn't masked by the pipeline
    local kata_deploy_values
    kata_deploy_values=$(yq -r 'select(.kind == "HelmChart" and .metadata.name == "kata-deploy").spec.valuesContent' \
        "$SCRIPT_DIR/manifests/trusted-compute.yaml") \
        || { print_error "yq failed to extract kata-deploy values from manifest"; exit 1; }
    if [[ -z "$kata_deploy_values" ]] || [[ "$kata_deploy_values" == "null" ]]; then
        print_error "yq returned empty/null valuesContent for kata-deploy HelmChart in manifest"
        exit 1
    fi
    printf '%s\n' "$kata_deploy_values" \
        | sed 's/k8sDistribution: "k3s"/k8sDistribution: "k8s"/' \
        > "$k8s_dir/values-kata-deploy.yaml"

    helm upgrade --install kata-deploy "$SCRIPT_DIR/charts/kata-deploy"*.tgz \
        --namespace kata-deploy -f "$k8s_dir/values-kata-deploy.yaml" \
        --set imagePullPolicy=IfNotPresent \
        --wait --timeout 3m && print_status "kata-deploy chart installed" \
        || { print_error "Failed to install kata-deploy chart"; exit 1; }

    # Install trusted-workload chart
    print_status "Installing trusted-workload chart..."
    helm upgrade --install trusted-workload "$SCRIPT_DIR/charts/trusted-workload"*.tgz \
        --namespace kata-deploy \
        --wait --timeout 3m \
        && print_status "trusted-workload chart installed" \
        || { print_error "Failed to install trusted-workload chart"; exit 1; }

    # Install attestation-verifier chart
    print_status "Installing attestation-verifier chart..."
    helm upgrade --install attestation-verifier "$SCRIPT_DIR/charts/attestation-verifier"*.tgz \
        --namespace trusted-compute \
        --set attestation-manager.env.pollDuration=5 \
        --set attestation-manager.env.InformAMServer="false" \
        --set attestation-manager.image.repository="${tc_registry}/attestation-manager" \
        --set attestation-manager.image.tag="$ATTESTATION_MANAGER_VERSION" \
        --wait --timeout 5m \
        && print_status "attestation-verifier chart installed" \
        || print_warning "attestation-verifier chart install did not report ready within timeout; continuing anyway"
}

# Function to update containerd config for K8s
update_containerd_config_k8s() {
    print_status "Updating containerd configuration..."

    # Record pre-modification state so uninstall.sh can fully restore it later
    local config_backup="${K8S_CONTAINERD_CONFIG}.tc-orig"
    local config_generated_marker="${K8S_CONTAINERD_DIR}/.tc-config-generated"

    # Generate default config.toml if it doesn't exist or is empty
    if [[ ! -s "$K8S_CONTAINERD_CONFIG" ]]; then
        mkdir -p "$K8S_CONTAINERD_DIR"
        containerd config default > "$K8S_CONTAINERD_CONFIG" \
            && print_status "Generated default containerd config.toml" \
            || { print_error "Failed to generate default containerd config"; exit 1; }
        touch "$config_generated_marker"
    else
        print_status "Existing containerd config.toml found, keeping it"
        [[ -f "$config_backup" ]] || cp "$K8S_CONTAINERD_CONFIG" "$config_backup"
    fi

    # Ensure imports line is present so conf.d snippets are loaded
    if grep -Eq '^[[:space:]]*imports[[:space:]]*=' "$K8S_CONTAINERD_CONFIG"; then
        if ! grep -Eq '^[[:space:]]*imports[[:space:]]*=.*conf\.d/\*\.toml' "$K8S_CONTAINERD_CONFIG"; then
            sed -i -E 's#^[[:space:]]*imports[[:space:]]*=[[:space:]]*\[(.*)\]#imports = [\1, "/etc/containerd/conf.d/*.toml"]#' "$K8S_CONTAINERD_CONFIG"
            sed -i 's/\[, /[/' "$K8S_CONTAINERD_CONFIG"
            print_status "Updated existing imports line to include conf.d"
        fi
    else
        sed -i '/^[[:space:]]*version[[:space:]]*=/a imports = ["/etc/containerd/conf.d/*.toml"]' "$K8S_CONTAINERD_CONFIG"
        print_status "Added conf.d imports to config.toml"
    fi

    # Install kata runtime as a conf.d drop-in
    mkdir -p "$K8S_CONTAINERD_DIR/conf.d"
    grep -v '{{ template' "$CONTAINERD_CONFIG_SRC" \
        | grep -v '/var/lib/rancher/k3s' \
        > "$K8S_CONTAINERD_DIR/conf.d/kata-qemu.toml" \
        && print_status "Installed kata-qemu drop-in to $K8S_CONTAINERD_DIR/conf.d/kata-qemu.toml" \
        || { print_error "Failed to install kata-qemu drop-in"; exit 1; }

    # Restart containerd to apply changes
    restart_containerd
}

# Function to print summary (TC installation for K8s)
print_tc_k8s_summary() {
    print_status "Installation completed successfully!"
    print_status "Summary of installed components (TC installation for K8s):"
    echo "  - Images imported to containerd namespace: k8s.io"
    echo "  - Helm charts installed: attestation-verifier, kata-deploy, trusted-workload"
    echo "  - Namespaces created: trusted-compute, kata-deploy"
    echo "  - Users and groups: bm-agents group, tc-agent user, tc-ima user"
    echo "  - Containerd config updated: $K8S_CONTAINERD_DIR"
}

install_tc_k8s() {
    setup_kubeconfig
    check_no_tc_docker_conflict
    check_no_tc_k3s_conflict
    check_secure_boot
    check_k8s_cluster
    check_node_taints
    print_status "Installation script running from: $SCRIPT_DIR"
    check_tc_requirements k8s
    print_status "Starting TC installation for K8s..."
    import_images_to_containerd
    update_containerd_config_k8s
    create_users_groups
    install_helm_charts_k8s
    print_tc_k8s_summary
    print_status "Wait for daemonsets and deployments to become ready..."
    sleep 60
    wait_for_namespace_ready "trusted-compute" "$TIMEOUT"
}

install_tc_k3s() {
    check_no_tc_docker_conflict
    check_no_tc_k8s_conflict
    check_secure_boot
    check_k3s_service
    print_status "Installation script running from: $SCRIPT_DIR"
    check_tc_requirements k3s
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
    wait_for_namespace_ready "trusted-compute" "$TIMEOUT"
}

install_tc_docker() {
    check_no_tc_k3s_conflict
    check_no_tc_k8s_conflict
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
    local options=("K3s    - TC installation for K3s" "K8s    - TC installation for K8s" "Docker - TC installation for Docker")
    local selected=0 key k2 k3
    local -a modes=(k3s k8s docker)

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
    TIMEOUT=$((10*60))
    DEPLOYMENT_OPTION=""

    # Parse argument
    case "${1:-}" in
        --k3s)    DEPLOYMENT_OPTION="k3s" ;;
        --k8s)    DEPLOYMENT_OPTION="k8s" ;;
        --docker) DEPLOYMENT_OPTION="docker" ;;
        "")       : ;;  # will prompt below
        *)
            print_error "Unknown argument: $1"
            echo "Usage: $0 [--k3s | --k8s | --docker]"
            exit 1
            ;;
    esac

    check_root

    # If no option given, show interactive menu
    [[ -z "$DEPLOYMENT_OPTION" ]] && select_deployment_option

    case "$DEPLOYMENT_OPTION" in
        k3s)    install_tc_k3s ;;
        k8s)    install_tc_k8s ;;
        docker) install_tc_docker ;;
    esac
}

[[ "${1:-}" == "--source-only" ]] && return 0
main "$@"
