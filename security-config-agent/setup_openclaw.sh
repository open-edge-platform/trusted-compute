#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Deploys OVMS, the OpenClaw gateway, and a separate privileged OpenClaw node
# with Docker Compose. The gateway uses the official OpenClaw image unchanged;
# only the security node adds the host-inspection utilities used by the skills.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_CONFIG_FILE="$SRC_DIR/model-configs.conf"
COMPOSE_FILE="$SRC_DIR/docker-compose.yml"
ENV_FILE="$SRC_DIR/.env"

OPENCLAW_VERSION="2026.8.2"
OPENCLAW_IMAGE=""
SECURITY_NODE_IMAGE="openclaw-security-node:local"
REDEPLOY_ONLY=0

OVMS_IMAGE="openvino/model_server:weekly"
OVMS_PORT="8000"
OVMS_MODEL="OpenVINO/Qwen3.5-9B-int8-ov"
OVMS_TOOL_PARSER=""
OVMS_TARGET_DEVICE="GPU"
OVMS_CACHE_SIZE=""
OVMS_READY_TIMEOUT=1800

STATE_ROOT="${OPENCLAW_STATE_ROOT:-$HOME/.openclaw-security-config-agent}"
MODELS_DIR="$HOME/models"
GATEWAY_PORT=18789
SECURITY_NODE_NAME="security-node"
AGENT_ID="main"
AGENT_WORKSPACE="/home/node/.openclaw/workspace"
SKILLS_SOURCE_DIR="$SRC_DIR/skills"
SKILLS_JSON=""

MODEL_TIMEOUT_SECONDS=600
MODEL_CONTEXT_TOKENS=""
MODEL_MAX_TOKENS=32768
MODEL_TEMPERATURE=0

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

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --openclaw-version <v>  Official OpenClaw image tag (default: ${OPENCLAW_VERSION})
  --openclaw-image <ref>  Official image reference (overrides --openclaw-version)
  --ovms-image <image>    OVMS image (default: ${OVMS_IMAGE})
  --ovms-port <port>      Host OVMS status port (default: ${OVMS_PORT})
  --ovms-model <id>       Model served by OVMS (default: ${OVMS_MODEL})
  --models-dir <path>     Host model repository (default: ${MODELS_DIR})
  --state-root <path>     Persistent deployment state (default: ${STATE_ROOT})
  --redeploy-only         Refresh containers and config without rebuilding the security node
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
            --openclaw-image)
                require_value "$@"
                OPENCLAW_IMAGE="$2"
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
            --state-root)
                require_value "$@"
                STATE_ROOT="$2"
                shift 2
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

    OPENCLAW_IMAGE="${OPENCLAW_IMAGE:-ghcr.io/openclaw/openclaw:${OPENCLAW_VERSION}}"

    if [[ ! "$OVMS_PORT" =~ ^[0-9]+$ ]] || (( OVMS_PORT < 1 || OVMS_PORT > 65535 )); then
        echo "ERROR: invalid port: '$OVMS_PORT'" >&2
        exit 1
    fi
    if [[ ! "$OPENCLAW_VERSION" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "ERROR: invalid OpenClaw version: '$OPENCLAW_VERSION'" >&2
        exit 1
    fi
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

    if [[ $matched -eq 0 || -z "$OVMS_TOOL_PARSER" ||
        ! "$OVMS_CACHE_SIZE" =~ ^[0-9]+$ ||
        ! "$MODEL_CONTEXT_TOKENS" =~ ^[0-9]+$ || -n "$extra" ]] ||
        (( MODEL_CONTEXT_TOKENS < MODEL_MAX_TOKENS )); then
        echo "ERROR: invalid or missing profile for '$OVMS_MODEL' in $MODEL_CONFIG_FILE" >&2
        exit 1
    fi
}

load_skills() {
    local file name
    local -a names=()

    for file in "$SKILLS_SOURCE_DIR"/*/SKILL.md; do
        [[ -f "$file" ]] || continue
        name="$(awk '/^name:[[:space:]]*/ { sub(/^name:[[:space:]]*/, ""); print; exit }' "$file")"
        if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
            echo "ERROR: invalid or missing skill name in $file" >&2
            exit 1
        fi
        names+=("$name")
    done

    if [[ ${#names[@]} -eq 0 ]]; then
        echo "ERROR: no skills found under $SKILLS_SOURCE_DIR" >&2
        exit 1
    fi

    SKILLS_JSON="$(printf '%s\n' "${names[@]}" | jq -R . | jq -s .)"
}

require_commands() {
    local command
    for command in docker curl jq openssl; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "ERROR: required command not found: $command" >&2
            exit 1
        fi
    done
    if ! docker compose version >/dev/null 2>&1; then
        echo "ERROR: Docker Compose v2 is required." >&2
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: cannot talk to the Docker daemon." >&2
        exit 1
    fi
    if [[ ! -d /dev/dri ]]; then
        echo "ERROR: /dev/dri is required for OVMS target device ${OVMS_TARGET_DEVICE}." >&2
        exit 1
    fi
}

compose() {
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

read_existing_token() {
    [[ -f "$ENV_FILE" ]] || return 0
    sed -n 's/^OPENCLAW_GATEWAY_TOKEN=//p' "$ENV_FILE" | tail -n 1
}

write_environment() {
    local gateway_token render_gid
    gateway_token="$(read_existing_token)"
    gateway_token="${gateway_token:-$(openssl rand -hex 32)}"
    render_gid="$(stat -c '%g' "$(ls /dev/dri/render* | head -n 1)")"

    mkdir -p "$STATE_ROOT/gateway" "$STATE_ROOT/workspace" \
        "$STATE_ROOT/security-node" "$MODELS_DIR"
    chmod 700 "$STATE_ROOT/gateway" "$STATE_ROOT/security-node"

    cat >"$ENV_FILE" <<EOF
OPENCLAW_IMAGE=$OPENCLAW_IMAGE
SECURITY_NODE_IMAGE=$SECURITY_NODE_IMAGE
OPENCLAW_GATEWAY_TOKEN=$gateway_token
GATEWAY_CONFIG_DIR=$STATE_ROOT/gateway
GATEWAY_WORKSPACE_DIR=$STATE_ROOT/workspace
SECURITY_NODE_STATE_DIR=$STATE_ROOT/security-node
GATEWAY_PORT=$GATEWAY_PORT
OVMS_IMAGE=$OVMS_IMAGE
OVMS_PORT=$OVMS_PORT
OVMS_MODEL=$OVMS_MODEL
OVMS_TOOL_PARSER=$OVMS_TOOL_PARSER
OVMS_TARGET_DEVICE=$OVMS_TARGET_DEVICE
OVMS_CACHE_SIZE=$OVMS_CACHE_SIZE
MODELS_DIR=$MODELS_DIR
HOST_UID=$(id -u)
HOST_GID=$(id -g)
RENDER_GID=$render_gid
EOF
    chmod 600 "$ENV_FILE"
}

install_skills() {
    local destination="$STATE_ROOT/workspace/skills"

    echo "Installing OpenClaw skills into $destination..."
    mkdir -p "$destination"
    cp -R "$SKILLS_SOURCE_DIR/." "$destination/"
}

prepare_images() {
    echo "Pulling the official OpenClaw and OVMS images..."
    compose pull openclaw-gateway openclaw-cli ovms
    if [[ $REDEPLOY_ONLY -eq 0 ]] || ! docker image inspect "$SECURITY_NODE_IMAGE" >/dev/null 2>&1; then
        echo "Building the security node utility layer..."
        compose build --pull security-node
    fi
}

agents_section() {
    jq -n \
        --arg id "$AGENT_ID" \
        --arg workspace "$AGENT_WORKSPACE" \
        --arg ref "$MODEL_REF" \
        --arg alias "$MODEL_NAME" \
        --argjson skills "$SKILLS_JSON" \
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
                list: [{ id: $id, workspace: $workspace, skills: $skills }]
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
                bind: "lan",
                tailscale: { mode: "off", resetOnExit: false },
                nodes: {
                    allowCommands: ["system.execApprovals.get", "system.execApprovals.set"],
                    denyCommands: $ARGS.positional
                }
            }
        }' \
        --args "${GATEWAY_DENY_COMMANDS[@]}"
}

tools_section() {
    jq -n \
        --arg node "$SECURITY_NODE_NAME" \
        '{
            tools: {
                exec: {
                    host: "node",
                    mode: "allowlist",
                    node: $node
                },
                elevated: { enabled: false }
            }
        }'
}

models_section() {
    jq -n \
        --arg baseUrl "http://ovms:8000/v3" \
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
    local -a patch_args=()
    if [[ $REDEPLOY_ONLY -eq 1 ]]; then
        patch_args=(--replace-path models.providers.ovms.models)
    fi

    echo "Applying the OpenClaw configuration..."
    emit_config | compose run -T --rm --no-deps --entrypoint node openclaw-gateway \
        dist/index.js config patch "${patch_args[@]}" --stdin
}

wait_for_ovms() {
    local url="http://127.0.0.1:${OVMS_PORT}/v3/models"
    local deadline=$((SECONDS + OVMS_READY_TIMEOUT)) response
    echo "Waiting for OVMS model '${OVMS_MODEL}'..."
    while (( SECONDS < deadline )); do
        if response=$(curl -fsS --max-time 5 "$url" 2>/dev/null) &&
            jq -e --arg model "$OVMS_MODEL" '.data | any(.id == $model)' \
                >/dev/null <<<"$response"; then
            echo "OVMS is ready."
            return
        fi
        if [[ "$(compose ps --status exited -q ovms)" ]]; then
            echo "ERROR: OVMS exited; run: docker compose -f $COMPOSE_FILE logs ovms" >&2
            exit 1
        fi
        sleep 10
    done
    echo "ERROR: OVMS did not become ready within ${OVMS_READY_TIMEOUT}s." >&2
    exit 1
}

approve_security_node() {
    local deadline=$((SECONDS + 90)) request_id="" devices=""
    echo "Checking the security node pairing..."
    while (( SECONDS < deadline )); do
        devices=$(compose exec -T openclaw-gateway \
            node dist/index.js devices list --json 2>/dev/null || true)
        if jq -e --arg name "$SECURITY_NODE_NAME" \
            '.paired | any(.displayName == $name)' >/dev/null 2>&1 <<<"$devices"; then
            echo "Security node is already paired."
            return
        fi
        request_id=$(jq -r --arg name "$SECURITY_NODE_NAME" \
            '[.pending[]? | select(.displayName == $name)] | sort_by(.ts) | last | .requestId // empty' \
            2>/dev/null <<<"$devices" || true)
        if [[ -n "$request_id" ]]; then
            echo "Approving security node request ${request_id}..."
            compose exec -T openclaw-gateway \
                node dist/index.js devices approve "$request_id"
            compose restart security-node
            return
        fi
        sleep 3
    done
    echo "ERROR: no pairing request received from '$SECURITY_NODE_NAME'." >&2
    echo "       Check: docker compose -f $COMPOSE_FILE logs security-node" >&2
    exit 1
}

approve_security_node_commands() {
    local deadline=$((SECONDS + 90)) request_id="" nodes=""
    echo "Checking the security node command approval..."
    while (( SECONDS < deadline )); do
        nodes=$(compose exec -T openclaw-gateway \
            node dist/index.js nodes status --json 2>/dev/null || true)
        if jq -e --arg name "$SECURITY_NODE_NAME" \
            '.nodes | any(.displayName == $name and .approvalState == "approved")' \
            >/dev/null 2>&1 <<<"$nodes"; then
            echo "Security node commands are already approved."
            return
        fi
        request_id=$(jq -r --arg name "$SECURITY_NODE_NAME" \
            '.nodes[]? | select(.displayName == $name) | .pendingRequestId // empty' \
            2>/dev/null <<<"$nodes" || true)
        if [[ -n "$request_id" ]]; then
            echo "Approving security node command request ${request_id}..."
            compose exec -T openclaw-gateway \
                node dist/index.js nodes approve "$request_id"
            compose restart security-node
            return
        fi
        sleep 3
    done
    echo "ERROR: no command approval request received from '$SECURITY_NODE_NAME'." >&2
    echo "       Check: docker compose -f $COMPOSE_FILE logs security-node" >&2
    exit 1
}

wait_for_security_node() {
    local deadline=$((SECONDS + 90)) nodes=""
    echo "Waiting for the security node to connect..."
    while (( SECONDS < deadline )); do
        nodes=$(compose exec -T openclaw-gateway \
            node dist/index.js nodes status --connected --json 2>/dev/null || true)
        if jq -e --arg name "$SECURITY_NODE_NAME" \
            '.nodes | any(.displayName == $name and .connected == true)' \
            >/dev/null 2>&1 <<<"$nodes"; then
            echo "Security node is connected."
            return
        fi
        sleep 3
    done
    echo "ERROR: '$SECURITY_NODE_NAME' did not connect after pairing." >&2
    echo "       Check: docker compose -f $COMPOSE_FILE logs security-node" >&2
    exit 1
}

verify_skills_available() {
    local report missing

    echo "Verifying OpenClaw skills for agent '$AGENT_ID'..."
    if ! report=$(compose exec -T openclaw-gateway \
        node dist/index.js skills list --agent "$AGENT_ID" --eligible --json); then
        echo "ERROR: failed to query the OpenClaw skill inventory." >&2
        exit 1
    fi

    missing=$(jq -n \
        --argjson expected "$SKILLS_JSON" \
        --argjson report "$report" \
        '$expected - ($report.skills | map(.name))')
    if ! jq -e 'length == 0' >/dev/null <<<"$missing"; then
        echo "ERROR: configured skills are missing or ineligible:" >&2
        jq -r '.[] | "  - \(.)"' <<<"$missing" >&2
        echo >&2
        compose exec -T openclaw-gateway \
            node dist/index.js skills list --agent "$AGENT_ID" --verbose || true
        exit 1
    fi

    echo "All configured skills are available: $(jq -r 'join(", ")' <<<"$SKILLS_JSON")"
}

configure_node_approvals() {
    echo "Applying cautious execution approvals to the security node..."
    compose exec -T openclaw-gateway node dist/index.js approvals set \
        --node "$SECURITY_NODE_NAME" --stdin <<'EOF'
{
  "version": 1,
  "defaults": {
    "security": "allowlist",
    "ask": "on-miss",
    "askFallback": "deny"
  }
}
EOF
}

print_summary() {
    echo
    echo "OpenClaw image: $OPENCLAW_IMAGE"
    echo "Gateway URL:    http://127.0.0.1:${GATEWAY_PORT}"
    echo "OVMS model:     $OVMS_MODEL ($OVMS_TARGET_DEVICE)"
    echo "OVMS status:    http://127.0.0.1:${OVMS_PORT}/v3/models"
    echo "Security node:  $SECURITY_NODE_NAME (privileged)"
    echo "State root:     $STATE_ROOT"
    echo
}

main() {
    parse_args "$@"
    load_model_config
    require_commands
    load_skills
    write_environment
    install_skills
    print_summary
    prepare_images
    configure_openclaw

    if [[ -n "$(compose ps -q openclaw-gateway)" ]]; then
        echo "Restarting the gateway to apply configuration updates..."
        compose restart openclaw-gateway
    fi
    compose up -d ovms openclaw-gateway security-node
    wait_for_ovms
    approve_security_node
    wait_for_security_node
    approve_security_node_commands
    wait_for_security_node
    configure_node_approvals
    compose restart openclaw-gateway security-node
    wait_for_security_node
    verify_skills_available

    echo
    echo "Deployment complete."
    echo "  Status: docker compose --env-file $ENV_FILE -f $COMPOSE_FILE ps"
    echo "  Logs:   docker compose --env-file $ENV_FILE -f $COMPOSE_FILE logs -f"
    echo "  UI:     http://127.0.0.1:${GATEWAY_PORT}"
    echo "  Token:  stored in $ENV_FILE (mode 0600)"
}

main "$@"
