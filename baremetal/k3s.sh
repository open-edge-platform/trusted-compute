#!/bin/bash
set -e

K3S_INSTALL_URL="https://get.k3s.io"
K3S_BIN="/usr/local/bin/k3s"
KUBECONFIG="$HOME/.kube/config"

check_sudo() {
    echo "ðŸ”‘ Checking sudo access..."
    if sudo -v; then
        echo "âœ… Sudo access verified."
    else
        echo "â›” Sudo access required. Exiting."
        exit 1
    fi
}

install_k3s() {
    echo "ðŸš€ Installing K3s..."
    curl -sfL $K3S_INSTALL_URL | sudo sh -
    echo "âœ… K3s installed."

    # Make kubeconfig usable without sudo
    mkdir -p ~/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml "$KUBECONFIG"
    sudo chown $USER:$USER "$KUBECONFIG"
    echo "âœ… Kubeconfig copied to $KUBECONFIG"
}

uninstall_k3s() {
    echo "ðŸ§¹ Uninstalling K3s..."
    sudo /usr/local/bin/k3s-uninstall.sh || sudo /usr/bin/k3s-uninstall.sh || true
    echo "âœ… K3s uninstalled."
}

check_k3s_service() {
    echo "ðŸ” Checking K3s service status..."
    if systemctl list-unit-files | grep -q '^k3s.service'; then
        if systemctl is-active --quiet k3s; then
            echo "âœ… K3s is running."
            return 0
        else
            echo "âš ï¸  K3s installed but not running."
            return 1
        fi
    else
        echo "â›” K3s not installed."
        return 2
    fi
}

detect_and_fix_port_conflicts() {
    echo "ðŸ”Ž Checking for port conflicts..."
    common_ports=(6443 10250 8472)
    conflict_found=0
    for port in "${common_ports[@]}"; do
        pid=$(sudo lsof -ti tcp:"$port" || true)
        if [[ -n "$pid" ]]; then
            echo "âš ï¸  Port $port in use by process $pid."
            read -rp "Kill process $pid using port $port? (y/n): " yn
            if [[ "$yn" =~ ^[Yy]$ ]]; then
                sudo kill "$pid"
                echo "âœ… Killed process $pid."
                conflict_found=1
            else
                echo "â­ï¸  Skipped port $port."
            fi
        fi
    done
    if [[ $conflict_found -eq 0 ]]; then
        echo "âœ… No port conflicts found."
    fi
}

get_yaml_from_user() {
    echo "ðŸ“„ Paste your YAML below (end with empty line):"
    lines=()
    while true; do
        read -r line
        [[ -z "$line" ]] && break
        lines+=("$line")
    done
    printf "%s\n" "${lines[@]}" > user_deployment.yaml
    echo "âœ… YAML saved to user_deployment.yaml"
}

choose_yaml() {
    read -rp "Use existing 'user_deployment.yaml'? (y/n): " answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        if [[ ! -s user_deployment.yaml ]]; then
            echo "âš ï¸  File not found or empty. Please paste new YAML."
            get_yaml_from_user
        else
            echo "âœ… Using existing file."
        fi
    else
        get_yaml_from_user
    fi
}

validate_yaml_file() {
    if [[ ! -s user_deployment.yaml ]]; then
        echo "â›” YAML file is missing or empty."
        exit 1
    fi
    if command -v yamllint &>/dev/null; then
        echo "ðŸ” Validating YAML with yamllint..."
        yamllint user_deployment.yaml || {
            echo "â›” YAML invalid. Fix and try again."
            exit 1
        }
    else
        echo "â„¹ï¸  yamllint not installed, skipping YAML check."
    fi
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --help              Show this help message.
  --version           Show installed K3s version.
  --install           Install or update K3s only.
  --uninstall         Uninstall K3s.
  --install_deploy    Install/upgrade K3s, fix conflicts, deploy YAML.
EOF
}

get_installed_version() {
    if [[ -x "$K3S_BIN" ]]; then
        sudo $K3S_BIN --version | awk '{print $3}'
    else
        echo "None"
    fi
}

get_latest_version() {
    curl -s https://api.github.com/repos/k3s-io/k3s/releases/latest | grep '"tag_name":' | head -1 | sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    if [[ $# -eq 0 ]]; then
        echo "â›” No arguments given. Use --help for usage."
        exit 1
    fi

    case "$1" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version)
            echo "Installed K3s version: $(get_installed_version)"
            exit 0
            ;;
        --install)
            check_sudo
            set +e
            check_k3s_service
            status=$?
            set -e
            if [[ $status -eq 0 ]]; then
                echo "âœ… K3s already running."
            else
                install_k3s
                sudo systemctl enable --now k3s
                echo "âœ… K3s installed & started."
            fi
            ;;
        --uninstall)
            check_sudo
            uninstall_k3s
            ;;
        --install_deploy)
            check_sudo
            set +e
            check_k3s_service
            status=$?
            set -e

            if [[ $status -eq 2 ]]; then
                echo "Installing K3s..."
                install_k3s
                sudo systemctl enable --now k3s
                sleep 5
            else
                installed=$(get_installed_version)
                latest=$(get_latest_version)
                echo "Installed: $installed"
                echo "Latest: $latest"
                if [[ "$installed" != "$latest" ]]; then
                    read -rp "New version available. Update? (y/n): " yn
                    if [[ "$yn" =~ ^[Yy]$ ]]; then
                        uninstall_k3s
                        install_k3s
                        sudo systemctl enable --now k3s
                        sleep 5
                    fi
                fi
            fi

            set +e
            check_k3s_service
            status=$?
            set -e

            if [[ $status -eq 1 ]]; then
                detect_and_fix_port_conflicts
                sudo systemctl restart k3s
                sleep 5
            fi

            export KUBECONFIG=$KUBECONFIG

            echo "Nodes:"
            kubectl get nodes || echo "âš ï¸  Could not get nodes."

            choose_yaml
            validate_yaml_file

            echo "ðŸš€ Applying deployment..."
            kubectl apply -f user_deployment.yaml

            echo "â³ Waiting..."
            sleep 10

            echo "Pods:"
            kubectl get pods

            echo "âœ… Done."
            ;;
        *)
            echo "â›” Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"


