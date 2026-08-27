#!/usr/bin/env bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

# Deployment files and generated secrets stay local to this sample by default.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LANGFUSE_DIR="${LANGFUSE_DIR:-${SCRIPT_DIR}/langfuse}"
LANGFUSE_COMPOSE_REF="${LANGFUSE_COMPOSE_REF:-b8248a752a8fb309f6a4da3497c72206f6e5927f}"
LANGFUSE_COMPOSE_URL="${LANGFUSE_COMPOSE_URL:-https://raw.githubusercontent.com/langfuse/langfuse/${LANGFUSE_COMPOSE_REF}/docker-compose.yml}"
LANGFUSE_COMPOSE_FILE="${LANGFUSE_DIR}/docker-compose.yml"
LANGFUSE_ENV_FILE="${LANGFUSE_ENV_FILE:-${LANGFUSE_DIR}/.env}"
LANGFUSE_BASE_URL="${LANGFUSE_BASE_URL:-http://localhost:3000}"

# The plugin source is required locally so npm and OpenClaw can install it.
PLUGIN_REPOSITORY="${PLUGIN_REPOSITORY:-https://github.com/langfuse/openclaw-x-langfuse-plugin.git}"
PLUGIN_DIR="${PLUGIN_DIR:-${SCRIPT_DIR}/openclaw-x-langfuse-plugin}"

log() {
    printf '[langfuse-openclaw] %s\n' "$*"
}

fail() {
    printf '[langfuse-openclaw] ERROR: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

random_hex() {
    openssl rand -hex "$1"
}

download_langfuse_compose() {
    local temporary_file="${LANGFUSE_COMPOSE_FILE}.tmp"

    mkdir -p "${LANGFUSE_DIR}"
    if [[ -f "${LANGFUSE_COMPOSE_FILE}" ]]; then
        log "Using existing Langfuse Compose file at ${LANGFUSE_COMPOSE_FILE}"
        return
    fi

    log "Downloading the Langfuse Compose file"
    if ! curl --fail --silent --show-error --location \
        --output "${temporary_file}" "${LANGFUSE_COMPOSE_URL}"; then
        rm -f "${temporary_file}"
        fail "Unable to download ${LANGFUSE_COMPOSE_URL}"
    fi
    mv "${temporary_file}" "${LANGFUSE_COMPOSE_FILE}"
}

clone_plugin_if_missing() {
    local repository="$1"
    local destination="$2"

    if [[ -d "${destination}/.git" ]]; then
        log "Using existing clone at ${destination}"
        return
    fi
    [[ ! -e "${destination}" ]] || fail "${destination} exists but is not a Git clone"
    git clone --depth 1 "${repository}" "${destination}"
}

read_env_value() {
    local key="$1"
    sed -n "s/^${key}=//p" "${LANGFUSE_ENV_FILE}" | tail -n 1
}

container_env_value() {
    local container="$1"
    local key="$2"

    docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "${container}" \
        | sed -n "s/^${key}=//p" | tail -n 1
}

openclaw_config_value() {
    local path="$1"

    openclaw config get "${path}" --json 2>/dev/null \
        | node -e 'let value = ""; process.stdin.on("data", chunk => value += chunk).on("end", () => process.stdout.write(JSON.parse(value)));'
}

adopt_existing_config() {
    local public_key secret_key

    public_key="$(openclaw_config_value plugins.entries.langfuse-bridge.config.publicKey || true)"
    secret_key="$(openclaw_config_value plugins.entries.langfuse-bridge.config.secretKey || true)"
    [[ -n "${public_key}" && -n "${secret_key}" ]] || \
        fail "The existing stack has no environment file and Langfuse project keys could not be recovered from OpenClaw"

    umask 077
    mkdir -p "$(dirname "${LANGFUSE_ENV_FILE}")"
    cat >"${LANGFUSE_ENV_FILE}" <<EOF
NEXTAUTH_URL=$(container_env_value langfuse-langfuse-web-1 NEXTAUTH_URL)
NEXTAUTH_SECRET=$(container_env_value langfuse-langfuse-web-1 NEXTAUTH_SECRET)
SALT=$(container_env_value langfuse-langfuse-worker-1 SALT)
ENCRYPTION_KEY=$(container_env_value langfuse-langfuse-worker-1 ENCRYPTION_KEY)
POSTGRES_PASSWORD=$(container_env_value langfuse-postgres-1 POSTGRES_PASSWORD)
DATABASE_URL=$(container_env_value langfuse-langfuse-worker-1 DATABASE_URL)
CLICKHOUSE_PASSWORD=$(container_env_value langfuse-clickhouse-1 CLICKHOUSE_PASSWORD)
MINIO_ROOT_PASSWORD=$(container_env_value langfuse-minio-1 MINIO_ROOT_PASSWORD)
LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY=$(container_env_value langfuse-langfuse-worker-1 LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY)
LANGFUSE_S3_MEDIA_UPLOAD_SECRET_ACCESS_KEY=$(container_env_value langfuse-langfuse-worker-1 LANGFUSE_S3_MEDIA_UPLOAD_SECRET_ACCESS_KEY)
LANGFUSE_S3_BATCH_EXPORT_SECRET_ACCESS_KEY=$(container_env_value langfuse-langfuse-worker-1 LANGFUSE_S3_BATCH_EXPORT_SECRET_ACCESS_KEY)
REDIS_AUTH=$(container_env_value langfuse-langfuse-worker-1 REDIS_AUTH)
OPENCLAW_LANGFUSE_PUBLIC_KEY=${public_key}
OPENCLAW_LANGFUSE_SECRET_KEY=${secret_key}
EOF
    log "Adopted the existing Langfuse configuration into ${LANGFUSE_ENV_FILE}"
}

langfuse_compose() {
    docker compose --project-directory "${LANGFUSE_DIR}" \
        --env-file "${LANGFUSE_ENV_FILE}" \
        --file "${LANGFUSE_COMPOSE_FILE}" "$@"
}

write_langfuse_config() {
    local postgres_password clickhouse_password minio_password redis_password
    local public_key secret_key admin_password

    if [[ -f "${LANGFUSE_ENV_FILE}" ]]; then
        chmod 600 "${LANGFUSE_ENV_FILE}"
        log "Reusing Langfuse configuration at ${LANGFUSE_ENV_FILE}"
        return
    fi
    if docker compose --project-directory "${LANGFUSE_DIR}" \
        --file "${LANGFUSE_COMPOSE_FILE}" ps -q | grep -q .; then
        adopt_existing_config
        return
    fi

    postgres_password="$(random_hex 24)"
    clickhouse_password="$(random_hex 24)"
    minio_password="$(random_hex 24)"
    redis_password="$(random_hex 24)"
    public_key="pk-lf-$(random_hex 16)"
    secret_key="sk-lf-$(random_hex 24)"
    admin_password="$(random_hex 24)"

    umask 077
    mkdir -p "$(dirname "${LANGFUSE_ENV_FILE}")"
    cat >"${LANGFUSE_ENV_FILE}" <<EOF
NEXTAUTH_URL=${LANGFUSE_BASE_URL}
NEXTAUTH_SECRET=$(openssl rand -base64 32 | tr -d '\n')
SALT=$(random_hex 32)
ENCRYPTION_KEY=$(random_hex 32)
POSTGRES_PASSWORD=${postgres_password}
DATABASE_URL=postgresql://postgres:${postgres_password}@postgres:5432/postgres
CLICKHOUSE_PASSWORD=${clickhouse_password}
MINIO_ROOT_PASSWORD=${minio_password}
LANGFUSE_S3_EVENT_UPLOAD_SECRET_ACCESS_KEY=${minio_password}
LANGFUSE_S3_MEDIA_UPLOAD_SECRET_ACCESS_KEY=${minio_password}
LANGFUSE_S3_BATCH_EXPORT_SECRET_ACCESS_KEY=${minio_password}
REDIS_AUTH=${redis_password}
LANGFUSE_INIT_ORG_ID=openclaw-org
LANGFUSE_INIT_ORG_NAME=OpenClaw
LANGFUSE_INIT_PROJECT_ID=openclaw-project
LANGFUSE_INIT_PROJECT_NAME=OpenClaw
LANGFUSE_INIT_PROJECT_PUBLIC_KEY=${public_key}
LANGFUSE_INIT_PROJECT_SECRET_KEY=${secret_key}
LANGFUSE_INIT_USER_EMAIL=${LANGFUSE_ADMIN_EMAIL:-admin@example.com}
LANGFUSE_INIT_USER_NAME=${LANGFUSE_ADMIN_NAME:-OpenClaw Admin}
LANGFUSE_INIT_USER_PASSWORD=${LANGFUSE_ADMIN_PASSWORD:-${admin_password}}
EOF
    log "Generated Langfuse configuration at ${LANGFUSE_ENV_FILE}"
}

configure_openclaw() {
    local public_key secret_key existing_allow merged_allow plugin_config

    public_key="$(read_env_value LANGFUSE_INIT_PROJECT_PUBLIC_KEY)"
    secret_key="$(read_env_value LANGFUSE_INIT_PROJECT_SECRET_KEY)"
    public_key="${public_key:-$(read_env_value OPENCLAW_LANGFUSE_PUBLIC_KEY)}"
    secret_key="${secret_key:-$(read_env_value OPENCLAW_LANGFUSE_SECRET_KEY)}"
    [[ -n "${public_key}" && -n "${secret_key}" ]] || \
        fail "Langfuse project keys are missing from ${LANGFUSE_ENV_FILE}"

    existing_allow="$(openclaw config get plugins.allow --json 2>/dev/null || printf '[]')"
    merged_allow="$(node -e '
const value = JSON.parse(process.argv[1]);
if (!Array.isArray(value)) throw new Error("plugins.allow must be an array");
console.log(JSON.stringify([...new Set([...value, "langfuse-bridge"])]));
' "${existing_allow}")"
    plugin_config="$(node -e '
console.log(JSON.stringify({
  enabled: true,
  config: { publicKey: process.argv[1], secretKey: process.argv[2], baseUrl: process.argv[3] }
}));
' "${public_key}" "${secret_key}" "${LANGFUSE_BASE_URL}")"

    openclaw config set plugins.allow "${merged_allow}" --strict-json
    openclaw config set plugins.entries.langfuse-bridge "${plugin_config}" --strict-json
    openclaw config validate
}

main() {
    require_command curl
    require_command docker
    require_command git
    require_command node
    require_command npm
    require_command openclaw
    require_command openssl
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

    # Download only the upstream file needed to run the Langfuse stack.
    download_langfuse_compose
    write_langfuse_config

    log "Deploying Langfuse"
    langfuse_compose up -d --wait --wait-timeout "${LANGFUSE_WAIT_TIMEOUT:-180}"

    clone_plugin_if_missing "${PLUGIN_REPOSITORY}" "${PLUGIN_DIR}"
    log "Installing plugin dependencies"
    npm --prefix "${PLUGIN_DIR}" ci --omit=dev
    log "Installing the Langfuse plugin in OpenClaw"
    openclaw plugins install "${PLUGIN_DIR}" --link

    log "Configuring OpenClaw"
    configure_openclaw
    openclaw gateway restart

    log "Deployment complete"
    log "Langfuse URL: ${LANGFUSE_BASE_URL}"
    log "Credentials: ${LANGFUSE_ENV_FILE} (mode 600)"
    langfuse_compose ps
    openclaw gateway status
}

main "$@"
