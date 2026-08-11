#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/
#
# Sets up OpenClaw on top of a local OpenVINO Model Server (OVMS):
# installs the base packages and Homebrew, starts OVMS with a GPU-backed
# text-generation model, installs the OpenClaw CLI, applies the config
# below so the agent talks to the local OVMS endpoint and installs the
# security configuration skills.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPENCLAW_VERSION="2026.7.1-2"
OPENCLAW_INSTALL_URL="https://openclaw.ai/install.sh"
OVMS_IMAGE="openvino/model_server:2026.3-gpu"
OVMS_CONTAINER="ovms"
OVMS_PORT="8000"
OVMS_MODEL="OpenVINO/Qwen3-8B-int4-ov"
OVMS_TARGET_DEVICE="GPU"
MODELS_DIR="$HOME/models"
OVMS_READY_TIMEOUT=1800

SKIP_OPENCLAW_INSTALL=0

# Knobs baked into the generated OpenClaw config.
AGENT_WORKSPACE="~/.openclaw/workspace"
GATEWAY_PORT=18789
MODEL_TIMEOUT_SECONDS=300
MODEL_CONTEXT_TOKENS=32768
MODEL_MAX_TOKENS=8192

# Node commands the local gateway must refuse.
GATEWAY_DENY_COMMANDS=(
    camera.snap
    camera.clip
    screen.record
    contacts.add
    calendar.add
    reminders.add
    sms.send
    sms.search
)

# Packages required by the Homebrew installer, the OpenClaw install script and
# the config generation.
APT_PACKAGES=(build-essential curl git jq procps)
BREW_PREFIX="/home/linuxbrew/.linuxbrew"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --openclaw-version <v>  OpenClaw version to install (default: ${OPENCLAW_VERSION})
  --ovms-image <image>    OVMS container image (default: ${OVMS_IMAGE})
  --ovms-port <port>      Host port for the OVMS REST endpoint (default: ${OVMS_PORT})
  --ovms-model <id>       Model served by OVMS (default: ${OVMS_MODEL})
  --target-device <dev>   OVMS target device, e.g. GPU or CPU (default: ${OVMS_TARGET_DEVICE})
  --models-dir <path>     Host model repository (default: ${MODELS_DIR})
  --skip-openclaw-install Use the already installed OpenClaw CLI
  -h, --help              Show this help
EOF
}

require_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        echo "ERROR: $1 requires a value" >&2
        usage >&2
        exit 1
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --openclaw-version)
                require_value "$@"
                OPENCLAW_VERSION="$2"
                shift 2
                ;;
            --ovms-image)
                require_value "$@"
                OVMS_IMAGE="$2"
                shift 2
                ;;
            --ovms-port)
                require_value "$@"
                OVMS_PORT="$2"
                shift 2
                ;;
            --ovms-model)
                require_value "$@"
                OVMS_MODEL="$2"
                shift 2
                ;;
            --target-device)
                require_value "$@"
                OVMS_TARGET_DEVICE="$2"
                shift 2
                ;;
            --models-dir)
                require_value "$@"
                MODELS_DIR="$2"
                shift 2
                ;;
            --skip-openclaw-install)
                SKIP_OPENCLAW_INSTALL=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "ERROR: unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
        esac
    done

    if [[ ! "$OVMS_PORT" =~ ^[0-9]+$ ]] || (( OVMS_PORT < 1 || OVMS_PORT > 65535 )); then
        echo "ERROR: invalid port: '$OVMS_PORT'" >&2
        exit 1
    fi

    if [[ ! "$OPENCLAW_VERSION" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "ERROR: invalid OpenClaw version: '$OPENCLAW_VERSION'" >&2
        exit 1
    fi

    # The model id also names a Docker source model and an OpenClaw model ref.
    if [[ ! "$OVMS_MODEL" =~ ^[A-Za-z0-9._/-]+$ ]]; then
        echo "ERROR: invalid OVMS model id: '$OVMS_MODEL'" >&2
        exit 1
    fi
}

sudo_cmd() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

print_summary() {
    echo "OpenClaw version: $OPENCLAW_VERSION"
    echo "OVMS image:       $OVMS_IMAGE"
    echo "OVMS model:       $OVMS_MODEL ($OVMS_TARGET_DEVICE)"
    echo "OVMS endpoint:    http://127.0.0.1:${OVMS_PORT}/v3"
    echo "Models dir:       $MODELS_DIR"
    echo
}

check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: docker not found - install Docker Engine first." >&2
        exit 1
    fi

    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: cannot talk to the Docker daemon - is it running and is" >&2
        echo "       '$USER' in the 'docker' group?" >&2
        exit 1
    fi
}

install_apt_packages() {
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "WARNING: apt-get not found - install manually: ${APT_PACKAGES[*]}"
        return
    fi

    echo "Installing packages: ${APT_PACKAGES[*]}"
    sudo_cmd apt-get update
    sudo_cmd apt-get install -y "${APT_PACKAGES[@]}"
}

# Homebrew provides the runtime the OpenClaw installer expects on Linux.
install_homebrew() {
    if ! command -v brew >/dev/null 2>&1; then
        echo "Installing Homebrew..."
        NONINTERACTIVE=1 /bin/bash -c \
            "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    else
        echo "Homebrew already installed: $(brew --version | head -n1)"
    fi

    local shellenv="eval \"\$(${BREW_PREFIX}/bin/brew shellenv)\""
    if [[ -x "${BREW_PREFIX}/bin/brew" ]]; then
        eval "$(${BREW_PREFIX}/bin/brew shellenv)"
        if ! grep -qxF "$shellenv" "$HOME/.bashrc" 2>/dev/null; then
            echo "$shellenv" >>"$HOME/.bashrc"
        fi
    fi
}

install_dependencies() {
    install_apt_packages
    install_homebrew
    echo
}

# OVMS needs the render node group id so the unprivileged container user can
# reach the iGPU/dGPU.
render_group_id() {
    local node
    node=$(ls /dev/dri/render* 2>/dev/null | head -n1 || true)
    [[ -n "$node" ]] && stat -c "%g" "$node"
}

start_ovms() {
    local -a device_args=()
    local render_gid
    render_gid=$(render_group_id)

    if [[ -n "$render_gid" ]]; then
        device_args=(--device /dev/dri --group-add "$render_gid")
    elif [[ "$OVMS_TARGET_DEVICE" == "GPU" ]]; then
        echo "ERROR: no /dev/dri render node found but --target-device is GPU." >&2
        echo "       Install the GPU drivers or rerun with --target-device CPU." >&2
        exit 1
    fi

    if docker ps -a --format '{{.Names}}' | grep -qx "$OVMS_CONTAINER"; then
        echo "Removing existing '$OVMS_CONTAINER' container..."
        docker rm -f "$OVMS_CONTAINER" >/dev/null
    fi

    mkdir -p "$MODELS_DIR"

    echo "Starting OVMS (first run downloads the model, this takes a while)..."
    docker run -d \
        --name "$OVMS_CONTAINER" \
        --user "$(id -u):$(id -g)" \
        "${device_args[@]}" \
        -p "${OVMS_PORT}:8000" \
        -v "${MODELS_DIR}:/models" \
        "$OVMS_IMAGE" \
        --source_model "$OVMS_MODEL" \
        --model_repository_path /models \
        --task text_generation \
        --tool_parser hermes3 \
        --rest_port 8000 \
        --target_device "$OVMS_TARGET_DEVICE" \
        --cache_size 4
}

wait_for_ovms() {
    local url="http://localhost:${OVMS_PORT}/v3/models"
    local deadline=$((SECONDS + OVMS_READY_TIMEOUT))

    echo "Waiting for OVMS at ${url}..."
    while (( SECONDS < deadline )); do
        if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
            echo "OVMS is serving:"
            curl -fsS "$url"
            echo
            return
        fi
        if ! docker ps --format '{{.Names}}' | grep -qx "$OVMS_CONTAINER"; then
            echo "ERROR: the '$OVMS_CONTAINER' container exited - check 'docker logs $OVMS_CONTAINER'." >&2
            exit 1
        fi
        sleep 10
    done

    echo "ERROR: OVMS did not become ready within ${OVMS_READY_TIMEOUT}s." >&2
    echo "       Check 'docker logs $OVMS_CONTAINER'." >&2
    exit 1
}

install_openclaw() {
    if [[ $SKIP_OPENCLAW_INSTALL -eq 1 ]]; then
        echo "Skipping OpenClaw installation (--skip-openclaw-install)."
    else
        local installer
        installer=$(mktemp)
        # shellcheck disable=SC2064
        trap "rm -f '$installer'" RETURN

        echo "Downloading the OpenClaw installer from ${OPENCLAW_INSTALL_URL}..."
        curl -fsSL --proto '=https' --tlsv1.2 "$OPENCLAW_INSTALL_URL" -o "$installer"
        echo "Review it with: less $installer"

        echo "Installing OpenClaw ${OPENCLAW_VERSION}..."
        bash "$installer" --version "$OPENCLAW_VERSION" --no-onboard
    fi

    if ! command -v openclaw >/dev/null 2>&1; then
        echo "ERROR: 'openclaw' not on PATH - open a new shell" >&2
        echo "       or source ~/.bashrc, then rerun." >&2
        exit 1
    fi
}

agents_section() {
    jq -n \
        --arg workspace "$AGENT_WORKSPACE" \
        --arg ref "$MODEL_REF" \
        --arg alias "$MODEL_NAME" \
        '{
            agents: {
                defaults: {
                    workspace: $workspace,
                    model: { primary: $ref },
                    models: { ($ref): { alias: $alias } }
                }
            }
        }'
}

gateway_section() {
    jq -n \
        --argjson port "$GATEWAY_PORT" \
        '{
            gateway: {
                mode: "local",
                auth: { mode: "token" },
                port: $port,
                bind: "loopback",
                tailscale: { mode: "off", resetOnExit: false },
                nodes: { denyCommands: $ARGS.positional }
            }
        }' \
        --args "${GATEWAY_DENY_COMMANDS[@]}"
}

models_section() {
    jq -n \
        --arg baseUrl "http://127.0.0.1:${OVMS_PORT}/v3" \
        --arg id "$OVMS_MODEL" \
        --arg name "$MODEL_NAME" \
        --argjson timeout "$MODEL_TIMEOUT_SECONDS" \
        --argjson context "$MODEL_CONTEXT_TOKENS" \
        --argjson maxTokens "$MODEL_MAX_TOKENS" \
        '{
            models: {
                mode: "merge",
                providers: {
                    ovms: {
                        baseUrl: $baseUrl,
                        api: "openai-completions",
                        apiKey: "unused",
                        timeoutSeconds: $timeout,
                        models: [{
                            id: $id,
                            name: $name,
                            reasoning: false,
                            input: ["text"],
                            contextWindow: $context,
                            contextTokens: $context,
                            maxTokens: $maxTokens,
                            compat: {
                                requiresStringContent: true,
                                strictMessageKeys: true
                            }
                        }]
                    }
                }
            }
        }'
}

emit_config() {
    # The *_section helpers read these through bash's dynamic scoping.
    local -r MODEL_REF="ovms/${OVMS_MODEL}"
    local -r MODEL_NAME="${OVMS_MODEL##*/}"

    {
        agents_section
        gateway_section
        models_section
    } | jq -s 'add'
}

configure_openclaw() {
    local config
    config=$(mktemp)
    # shellcheck disable=SC2064
    trap "rm -f '$config'" RETURN
    emit_config >"$config"

    echo "Applying the OpenClaw config (OVMS ${OVMS_MODEL} on port ${OVMS_PORT})..."
    openclaw config patch --file "$config"

    echo "Installing the OpenClaw gateway..."
    openclaw gateway install
}

install_skills() {
    local script="$SRC_DIR/install_skills.sh"

    if [[ ! -f "$script" ]]; then
        echo "WARNING: $script not found - skills not installed."
        return
    fi

    echo
    echo "Installing the security configuration skills..."
    bash "$script"
}

print_next_steps() {
    echo
    echo "Done. Next steps:"
    echo "  - Check the gateway: openclaw gateway status"
}

main() {
    parse_args "$@"
    print_summary
    check_docker
    install_dependencies
    start_ovms
    wait_for_ovms
    install_openclaw
    configure_openclaw
    install_skills
    print_next_steps
}

main "$@"
