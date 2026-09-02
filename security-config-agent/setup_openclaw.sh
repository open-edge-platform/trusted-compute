#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Sets up OpenClaw on top of a local OpenVINO Model Server (OVMS):
# installs the base packages and Homebrew, starts a hardened OVMS container
# with a GPU-backed text-generation model, installs the OpenClaw CLI, applies
# the config below so the agent talks to the local OVMS endpoint and installs
# the security configuration skills.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_CONFIG_FILE="$SRC_DIR/model-configs.conf"

SKIP_OPENCLAW_INSTALL=0
REDEPLOY_ONLY=0
OPENCLAW_VERSION="2026.7.1-2"
OPENCLAW_INSTALL_TAG="v2026.7.1-2"
OPENCLAW_INSTALL_SHA256="957e20de009d6e41fcf8fe005705bc114172e185cd640f4811220ec645014324"
OPENCLAW_INSTALL_URL="https://openclaw.ai/install.sh"
OPENCLAW_INSTALL_FALLBACK_URL="https://raw.githubusercontent.com/openclaw/openclaw/${OPENCLAW_INSTALL_TAG}/scripts/install.sh"
# Last resort: some corporate proxies TLS-intercept openclaw.ai and
# raw.githubusercontent.com but leave the jsDelivr CDN alone.
OPENCLAW_INSTALL_MIRROR_URL="https://cdn.jsdelivr.net/gh/openclaw/openclaw@${OPENCLAW_INSTALL_TAG}/scripts/install.sh"

BREW_INSTALL_SNAPSHOT="cced90146ea6d3057c03a636b668fef177415eb3"
BREW_INSTALL_SHA256="12479a24be3f5307eecac7cde670fad7118640f031229e964f544b1367b52a41"
BREW_INSTALL_URL="https://raw.githubusercontent.com/Homebrew/install/${BREW_INSTALL_SNAPSHOT}/install.sh"
BREW_INSTALL_MIRROR_URL="https://cdn.jsdelivr.net/gh/Homebrew/install@${BREW_INSTALL_SNAPSHOT}/install.sh"

OVMS_IMAGE="openvino/model_server:weekly"
OVMS_CONTAINER="ovms"
OVMS_PORT="8000"
OVMS_MODEL="OpenVINO/Qwen3.5-9B-int8-ov"
OVMS_TOOL_PARSER=""
OVMS_TARGET_DEVICE="GPU"
OVMS_CACHE_SIZE=""
MODELS_DIR="$HOME/models"
OVMS_READY_TIMEOUT=1800

# Temp files removed by the EXIT trap.
TMP_FILES=()

# Knobs baked into the generated OpenClaw config.
# AGENT_ID must match the --agent default in install_skills.sh.
AGENT_ID="main"
AGENT_WORKSPACE="$HOME/.openclaw/workspace"
GATEWAY_PORT=18789

MODEL_TIMEOUT_SECONDS=600
MODEL_CONTEXT_TOKENS=""
MODEL_MAX_TOKENS=32768
MODEL_TEMPERATURE=0

# Channels allowed to run elevated (host) exec. The skills read platform
# security state through sudo (rdmsr, dmsetup, cryptsetup), which the agent
# cannot do unless its channel is on this allowlist. The gateway binds to
# loopback with token auth; `tools_section` grants each listed channel
# elevated access for any authenticated principal ("*").
ELEVATED_ALLOW_CHANNELS=(webchat)

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
BREW_DEFAULT_PREFIX="/home/linuxbrew/.linuxbrew"

cleanup() {
    local file
    for file in ${TMP_FILES[@]+"${TMP_FILES[@]}"}; do
        rm -f "$file"
    done
}
trap cleanup EXIT

make_temp_file() {
    local file
    file=$(mktemp)
    TMP_FILES+=("$file")
    printf '%s\n' "$file"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --openclaw-version <v>     OpenClaw version to install (default: ${OPENCLAW_VERSION})
  --ovms-image <image>       OVMS container image (default: ${OVMS_IMAGE})
  --ovms-port <port>         Host port for the OVMS REST endpoint (default: ${OVMS_PORT})
  --ovms-model <id>          Model served by OVMS (default: ${OVMS_MODEL})
  --models-dir <path>        Host model repository (default: ${MODELS_DIR})
  --skip-openclaw-install    Use the already installed OpenClaw CLI
  --redeploy-only            Redeploy OVMS plus the OpenClaw config/gateway only; skip dependency and skill installation
  -h, --help                 Show this help
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
            --models-dir)
                require_value "$@"
                MODELS_DIR="$2"
                shift 2
                ;;
            --skip-openclaw-install)
                SKIP_OPENCLAW_INSTALL=1
                shift
                ;;
            --redeploy-only)
                REDEPLOY_ONLY=1
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

load_model_config() {
    if [[ ! -r "$MODEL_CONFIG_FILE" ]]; then
        echo "ERROR: model config file not found or unreadable: $MODEL_CONFIG_FILE" >&2
        exit 1
    fi

    local model="" parser="" cache_size="" context="" extra="" line=""
    local matched=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        IFS='|' read -r model parser cache_size context extra <<<"$line"
        [[ "$model" == "$OVMS_MODEL" ]] || continue

        OVMS_TOOL_PARSER="$parser"
        OVMS_CACHE_SIZE="$cache_size"
        MODEL_CONTEXT_TOKENS="$context"
        matched=1
        break
    done <"$MODEL_CONFIG_FILE"

    if [[ $matched -eq 0 ]]; then
        echo "ERROR: no profile for '$OVMS_MODEL' in $MODEL_CONFIG_FILE" >&2
        exit 1
    fi

    if [[ -z "$OVMS_TOOL_PARSER" || ! "$OVMS_CACHE_SIZE" =~ ^[0-9]+$ ||
        ! "$MODEL_CONTEXT_TOKENS" =~ ^[0-9]+$ || -n "$extra" ]] ||
        (( MODEL_CONTEXT_TOKENS < MODEL_MAX_TOKENS )); then
        echo "ERROR: invalid profile for '$OVMS_MODEL' in $MODEL_CONFIG_FILE" >&2
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
    echo "Tool parser:      $OVMS_TOOL_PARSER"
    echo "Model context:    $MODEL_CONTEXT_TOKENS tokens"
    echo "Model max output: $MODEL_MAX_TOKENS tokens"
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
        local brew_installer
        brew_installer=$(make_temp_file)
        download_script "$brew_installer" "Homebrew installer" "$BREW_INSTALL_SHA256" \
            "$BREW_INSTALL_URL" "$BREW_INSTALL_MIRROR_URL"
        NONINTERACTIVE=1 /bin/bash "$brew_installer"
    else
        echo "Homebrew already installed: $(brew --version | head -n1)"
    fi

    local brew_bin
    brew_bin=$(command -v brew || true)
    if [[ -z "$brew_bin" && -x "${BREW_DEFAULT_PREFIX}/bin/brew" ]]; then
        brew_bin="${BREW_DEFAULT_PREFIX}/bin/brew"
    fi

    if [[ -z "$brew_bin" ]]; then
        echo "WARNING: brew not found after installation - shell environment not updated."
        return
    fi

    eval "$("$brew_bin" shellenv)"

    local shellenv="eval \"\$(${brew_bin} shellenv)\""
    if ! grep -qxF "$shellenv" "$HOME/.bashrc" 2>/dev/null; then
        echo "$shellenv" >>"$HOME/.bashrc"
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
        echo "ERROR: no /dev/dri render node found but the target device is GPU." >&2
        echo "       Install the GPU drivers, or set OVMS_TARGET_DEVICE to CPU." >&2
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
        --restart unless-stopped \
        --user "$(id -u):$(id -g)" \
        --read-only \
        --tmpfs /tmp:rw,nosuid,nodev \
        --cap-drop ALL \
        --security-opt no-new-privileges=true \
        "${device_args[@]}" \
        -p "127.0.0.1:${OVMS_PORT}:8000" \
        -v "${MODELS_DIR}:/models" \
        "$OVMS_IMAGE" \
        --source_model "$OVMS_MODEL" \
        --model_repository_path /models \
        --task text_generation \
        --tool_parser "$OVMS_TOOL_PARSER" \
        --rest_port 8000 \
        --target_device "$OVMS_TARGET_DEVICE" \
        --cache_size "$OVMS_CACHE_SIZE"
}

wait_for_ovms() {
    local url="http://127.0.0.1:${OVMS_PORT}/v3/models"
    local deadline=$((SECONDS + OVMS_READY_TIMEOUT))
    local response

    echo "Waiting for OVMS model '${OVMS_MODEL}' at ${url}..."
    while (( SECONDS < deadline )); do
        if response=$(curl -fsS --max-time 5 "$url" 2>/dev/null) &&
            jq -e --arg model "$OVMS_MODEL" \
                '.data | any(.id == $model)' \
                >/dev/null <<<"$response"; then
            echo "OVMS is serving:"
            printf '%s\n' "$response"
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

verify_script_checksum() {
    local file="$1" expected_sha256="$2" label="$3"

    if [[ -z "$expected_sha256" ]]; then
        return 0
    fi

    local actual_sha256
    actual_sha256=$(sha256sum "$file" | awk '{print $1}')
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
        echo "ERROR: ${label} SHA256 mismatch - expected ${expected_sha256}, got ${actual_sha256}." >&2
        return 1
    fi

    echo "Verified ${label} SHA256: ${expected_sha256}"
    return 0
}

# Tries each URL in order so a proxy that breaks one source does not block setup.
download_script() {
    local dest="$1" label="$2" expected_sha256="${3:-}" 
    shift 3
    local url

    for url in "$@"; do
        echo "Downloading the ${label} from ${url}..."
        if curl -fsSL --proto '=https' --tlsv1.2 "$url" -o "$dest"; then
            if verify_script_checksum "$dest" "$expected_sha256" "$label"; then
                return 0
            fi
            echo "WARNING: refusing to execute ${label} from ${url} due to checksum mismatch." >&2
            rm -f "$dest"
        else
            echo "WARNING: failed to download the ${label} from ${url}" >&2
        fi
    done

    echo "ERROR: could not download or verify the ${label}." >&2
    echo "       If this is a TLS error, your proxy is intercepting HTTPS and its" >&2
    echo "       root CA is missing. Install it with:" >&2
    echo "         sudo cp <root-ca>.crt /usr/local/share/ca-certificates/" >&2
    echo "         sudo update-ca-certificates" >&2
    exit 1
}

download_installer() {
    download_script "$1" "OpenClaw installer" "$OPENCLAW_INSTALL_SHA256" \
        "$OPENCLAW_INSTALL_URL" \
        "$OPENCLAW_INSTALL_FALLBACK_URL" \
        "$OPENCLAW_INSTALL_MIRROR_URL"
}

# The installer may drop the CLI in a bin dir that is not on PATH yet (e.g. the
# npm global prefix), so locate it and persist the PATH entry.
ensure_openclaw_on_path() {
    local dir npm_bin
    local -a candidates=("$HOME/.npm-global/bin" "$HOME/.local/bin" "$HOME/bin")

    command -v openclaw >/dev/null 2>&1 && return 0

    if command -v npm >/dev/null 2>&1; then
        npm_bin=$(npm prefix -g 2>/dev/null)/bin
        [[ -n "$npm_bin" ]] && candidates+=("$npm_bin")
    fi

    for dir in "${candidates[@]}"; do
        [[ -x "$dir/openclaw" ]] || continue

        export PATH="$dir:$PATH"
        local line="export PATH=\"$dir:\$PATH\""
        if ! grep -qxF "$line" "$HOME/.bashrc" 2>/dev/null; then
            echo "$line" >>"$HOME/.bashrc"
        fi
        echo "Found openclaw in $dir - added it to PATH."
        return 0
    done

    return 1
}

install_openclaw() {
    if [[ $SKIP_OPENCLAW_INSTALL -eq 1 ]]; then
        echo "Skipping OpenClaw installation (--skip-openclaw-install)."
    else
        local installer
        installer=$(make_temp_file)

        download_installer "$installer"
        echo "Review it with: less $installer"

        echo "Installing OpenClaw ${OPENCLAW_VERSION}..."
        bash "$installer" --version "$OPENCLAW_VERSION" --no-onboard
    fi

    if ! ensure_openclaw_on_path; then
        echo "ERROR: 'openclaw' not found - add its bin directory to PATH" >&2
        echo "       (see the installer output above), then rerun." >&2
        exit 1
    fi
}

agents_section() {
    jq -n \
        --arg id "$AGENT_ID" \
        --arg workspace "$AGENT_WORKSPACE" \
        --arg ref "$MODEL_REF" \
        --arg alias "$MODEL_NAME" \
        --argjson temperature "$MODEL_TEMPERATURE" \
        '{
            agents: {
                defaults: {
                    workspace: $workspace,
                    model: { primary: $ref },
                    models: {
                        ($ref): {
                            alias: $alias,
                            params: { temperature: $temperature }
                        }
                    }
                },
                list: [{ id: $id, workspace: $workspace }]
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

tools_section() {
    jq -n \
        '{
            tools: {
                elevated: {
                    enabled: ($ARGS.positional | length > 0),
                    allowFrom: (reduce $ARGS.positional[] as $c ({}; .[$c] = ["*"]))
                }
            }
        }' \
        --args "${ELEVATED_ALLOW_CHANNELS[@]}"
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
        tools_section
        models_section
    } | jq -s 'add'
}

configure_openclaw() {
    local config
    local -a patch_args=()
    config=$(make_temp_file)
    emit_config >"$config"

    if [[ $REDEPLOY_ONLY -eq 1 ]]; then
        patch_args=(--replace-path models.providers.ovms.models)
    fi

    echo "Applying the OpenClaw config (OVMS ${OVMS_MODEL} on port ${OVMS_PORT})..."
    # In a redeploy-only path we intentionally replace the OVMS model array at the
    # provider path so the prior model entry is removed and the new model takes its place.
    openclaw config patch "${patch_args[@]}" --file "$config"

    if openclaw gateway status >/dev/null 2>&1; then
        echo "Restarting the OpenClaw gateway..."
        openclaw gateway restart || openclaw gateway install
    else
        echo "Installing the OpenClaw gateway..."
        openclaw gateway install
    fi
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
    load_model_config
    print_summary
    check_docker

    if [[ $REDEPLOY_ONLY -eq 1 ]]; then

        if ! command -v openclaw >/dev/null 2>&1; then
            echo "ERROR: 'openclaw' CLI not found - install it first or omit --redeploy-only." >&2
            exit 1
        fi
        if ! command -v curl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
            echo "ERROR: 'curl' and 'jq' are required for --redeploy-only; install them or run without --redeploy-only." >&2
            exit 1
        fi
        start_ovms
        wait_for_ovms
        configure_openclaw
        echo
        echo "Redeploy complete. OpenClaw config refreshed and gateway restarted."
        echo "  - Check gateway: openclaw gateway status"
        return 0
    fi

    install_dependencies
    start_ovms
    wait_for_ovms
    install_openclaw
    configure_openclaw
    install_skills
    print_next_steps
}

main "$@"
