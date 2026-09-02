#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Installs the Security Configuration skills into an existing OpenClaw agent:
# installs the tools the skills shell out to, copies the skills/ tree into the
# agent workspace and updates the agent's skill allowlist in
# ~/.openclaw/openclaw.json.

set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

AGENT_ID="main"
SKILLS_DIR=""
AGENT_INDEX=""
SKILLS_JSON=""
CONFIG_SNIPPET=""
SKILL_NAMES=()
SKIP_DEPS=0

# Tools the skills invoke: rdmsr (boot-guard, tme), tpm2_pcrread (boot-guard),
# mokutil (secure-boot, trusted-compute-install), cryptsetup/dmsetup/lsblk
# (disk-encryption), oras (trusted-compute-install).
# curl/ca-certificates are needed to download the oras release tarball.
APT_PACKAGES=(msr-tools tpm2-tools mokutil cryptsetup dmsetup curl ca-certificates)
ORAS_VERSION="1.2.0"

# OpenClaw builds the gateway PATH from a fixed allowlist that on Linux covers
# only /usr/local/bin, /usr/bin, /bin and a few user bin dirs - sbin and snap
# dirs are excluded, so tools living there must be linked into ~/.local/bin or
# the skills requiring them stay ineligible.
LINK_DIR="$HOME/.local/bin"
LINK_SEARCH_PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/snap/bin"
LINKED_TOOLS=(rdmsr tpm2_pcrread mokutil cryptsetup dmsetup lsblk oras)

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --agent-id <id>      Existing OpenClaw agent id (default: ${AGENT_ID})
  --skills-dir <path>  Skills directory (default: the agent workspace's skills/)
  --skip-deps          Do not install the apt packages and oras CLI
  -h, --help           Show this help
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
            --agent-id)
                require_value "$@"
                AGENT_ID="$2"
                shift 2
                ;;
            --skills-dir)
                require_value "$@"
                SKILLS_DIR="$2"
                shift 2
                ;;
            --skip-deps)
                SKIP_DEPS=1
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

    if [[ ! "$AGENT_ID" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
        echo "ERROR: agent id must be lowercase alphanumeric with hyphens: '$AGENT_ID'" >&2
        exit 1
    fi
}

# Skill names come from the `name:` frontmatter of each skills/*/SKILL.md.
build_skills_json() {
    local file name sep=""

    SKILL_NAMES=()
    for file in "$SRC_DIR"/skills/*/SKILL.md; do
        [[ -f "$file" ]] || continue
        name="$(awk '/^name:[[:space:]]*/ { sub(/^name:[[:space:]]*/, ""); print; exit }' "$file")"
        if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
            echo "ERROR: invalid or missing skill name in $file" >&2
            exit 1
        fi
        SKILL_NAMES+=("$name")
    done

    if [[ ${#SKILL_NAMES[@]} -eq 0 ]]; then
        echo "ERROR: no skills found under $SRC_DIR/skills" >&2
        exit 1
    fi

    SKILLS_JSON="["
    for name in "${SKILL_NAMES[@]}"; do
        SKILLS_JSON+="${sep}\"${name}\""
        sep=","
    done
    SKILLS_JSON+="]"
}

# Agents live in the 'agents.list' array, so entries are addressed by index.
find_agent_index() {
    local i=0 id
    while id=$(openclaw config get "agents.list[$i].id" --json 2>/dev/null); do
        if [[ "$id" == "\"${AGENT_ID}\"" ]]; then
            printf '%s\n' "$i"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

resolve_agent_index() {
    if command -v openclaw >/dev/null 2>&1; then
        AGENT_INDEX=$(find_agent_index || true)
    fi
}

resolve_skills_dir() {
    [[ -n "$SKILLS_DIR" ]] && return

    local workspace=""
    if [[ -n "$AGENT_INDEX" ]]; then
        workspace=$(openclaw config get "agents.list[$AGENT_INDEX].workspace" --json 2>/dev/null | tr -d '"')
    fi
    SKILLS_DIR="${workspace:-$HOME/.openclaw/agents/$AGENT_ID/workspace}/skills"
}

build_config_snippet() {
    CONFIG_SNIPPET=$(cat <<EOF
{
  "agents": {
    "list": [
      {
        "id": "${AGENT_ID}",
        "skills": ${SKILLS_JSON}
      }
    ]
  }
}
EOF
)
}

print_summary() {
    echo "Agent id:    $AGENT_ID"
    echo "Skills dir:  $SKILLS_DIR"
    echo "Skills:      ${SKILL_NAMES[*]}"
    echo
}

sudo_cmd() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
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

# oras is not packaged for Ubuntu; pull the release tarball from GitHub.
install_oras() {
    if command -v oras >/dev/null 2>&1; then
        echo "oras already installed: $(oras version | head -n1)"
        return
    fi

    if ! command -v curl >/dev/null 2>&1; then
        echo "WARNING: curl not found - cannot download oras. Install curl (e.g."
        echo "         'apt-get install -y curl ca-certificates') and re-run, or install oras manually:"
        echo "         https://oras.land/docs/installation"
        return
    fi

    local arch tmp_dir url checksum_url tarball archive_path checksums_file
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *)
            echo "WARNING: unsupported architecture $(uname -m) - install oras manually:"
            echo "         https://oras.land/docs/installation"
            return
            ;;
    esac

    tmp_dir="$(mktemp -d)"
    tarball="oras_${ORAS_VERSION}_linux_${arch}.tar.gz"
    archive_path="$tmp_dir/$tarball"
    url="https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/${tarball}"
    checksum_url="https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_checksums.txt"
    checksums_file="$tmp_dir/oras_checksums.txt"
    trap 'rm -rf "$tmp_dir"; trap - RETURN' RETURN

    echo "Installing oras ${ORAS_VERSION} (${arch})..."
    if ! curl -fsSL "$url" -o "$archive_path"; then
        echo "WARNING: failed to download oras - install manually:"
        echo "         https://oras.land/docs/installation"
        return
    fi

    if ! curl -fsSL "$checksum_url" -o "$checksums_file"; then
        echo "WARNING: failed to download oras checksums - install manually:"
        echo "         https://oras.land/docs/installation"
        return
    fi

    if ! grep -F "  $tarball" "$checksums_file" >"$tmp_dir/oras.sha256"; then
        echo "WARNING: checksum entry missing for $tarball - install manually:"
        echo "         https://oras.land/docs/installation"
        return
    fi

    if ! (cd "$tmp_dir" && sha256sum -c oras.sha256 >/dev/null); then
        echo "WARNING: oras checksum verification failed - install manually:"
        echo "         https://oras.land/docs/installation"
        return
    fi

    tar -zxf "$archive_path" -C "$tmp_dir" oras
    sudo_cmd install -m 0755 "$tmp_dir/oras" /usr/local/bin/oras
}

link_tools() {
    local tool path

    echo "Linking skill tools into ${LINK_DIR}..."
    mkdir -p "$LINK_DIR"
    for tool in "${LINKED_TOOLS[@]}"; do
        path=$(PATH="$LINK_SEARCH_PATH" command -v "$tool" 2>/dev/null || true)
        if [[ -z "$path" ]]; then
            echo "  $tool: not found - skills requiring it stay unavailable"
            continue
        fi
        case "$path" in
            /usr/local/bin/*|/usr/bin/*|/bin/*) continue ;;
        esac
        ln -sfn "$path" "$LINK_DIR/$tool"
        echo "  $tool -> $path"
    done
}

install_dependencies() {
    if [[ $SKIP_DEPS -eq 1 ]]; then
        echo "Skipping dependency installation (--skip-deps)."
        return
    fi

    install_apt_packages
    install_oras
    link_tools
    echo
}

install_skills() {
    echo "Installing skills..."
    mkdir -p "$SKILLS_DIR"
    cp -R "$SRC_DIR/skills/." "$SKILLS_DIR/"
}

update_allowlist() {
    if [[ -z "$AGENT_INDEX" ]]; then
        echo
        echo "WARNING: agent '$AGENT_ID' not found in agents.list - allowlist not updated."
        echo "Create the agent first, or merge this manually:"
        echo
        echo "$CONFIG_SNIPPET"
        return
    fi

    echo "Merging skill allowlist for agents.list[$AGENT_INDEX]..."
    local existing_json merged_json name existing_names=()
    existing_json=$(openclaw config get "agents.list[$AGENT_INDEX].skills" --json 2>/dev/null || echo "[]")
    while IFS= read -r entry; do
        existing_names+=("$entry")
    done < <(printf '%s' "$existing_json" | grep -oP '"[^"]*"' | tr -d '"')

    merged_json="$SKILLS_JSON"
    for name in "${existing_names[@]}"; do
        if [[ ! " ${SKILL_NAMES[*]} " =~ " ${name} " ]]; then
            merged_json="${merged_json%]},\"${name}\"]"
        fi
    done

    if ! openclaw config set "agents.list[$AGENT_INDEX].skills" "$merged_json" --strict-json; then
        echo
        echo "WARNING: 'openclaw config set' failed - merge this manually instead:"
        echo
        echo "$CONFIG_SNIPPET"
        return
    fi

    echo
    echo "Verifying..."
    openclaw skills list --agent "$AGENT_ID" --eligible || true
}

restart_gateway() {
    echo
    echo "Restarting gateway to pick up the new skills..."
    if ! openclaw gateway restart; then
        echo "WARNING: 'openclaw gateway restart' failed - restart it manually."
    fi
}

main() {
    parse_args "$@"
    build_skills_json
    resolve_agent_index
    resolve_skills_dir
    build_config_snippet
    print_summary
    install_dependencies
    install_skills
    update_allowlist
    restart_gateway
}

main "$@"
