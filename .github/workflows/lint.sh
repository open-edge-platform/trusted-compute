#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2025 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o pipefail
set -o nounset

if [ -n "${TRACE:-}" ]; then
    set -o xtrace
fi

fail_on_match="${1:-true}"

# Keep list sorted in ascending order 🙏. Will search case insensitive so no need to add upper/lower case variants.
forbidden_words=(
    "amr-registry"
    "devtoolbox"
    "edge i"
    "edge iaas"
    "edge-i"
    "edgei"
    "ensp"
    "Fleet management"
    "fleetmanagement"
    "fmaas"
    "Iaas"
    "Ifm"
    "innersource"
    "Ledge park"
    "ledgepark"
    "lp-I"
    "Lpi"
    "maestro"
    "maestro-a"
    "maestroa"
    "maestro-c"
    "maestroc"
    "maestro-i"
    "maestroi"
    "one-intel-edge"
    "One Intel Edge"
    "open-registry"
    "open-file"
    "proxy-dmz.intel.com"
    "proxy.intel.com"
    "springboard"
    "strata"
    "tiber"
    "wireless guardian"
    "Wirelessguardian"
    "134.134.137.64"
    "134.134.139.64"
    "18.216.244.136"
    "18.217.166.151"
    "192.102.204.32"
    "192.198.146.160"
    "192.198.147.160"
    "192.55.46.32"
    "192.55.54.32"
    "192.55.55.32"
    "192.55.79.160"
    "198.175.68.32"
    "198.175.76.217"
    "134.134.139.64"
)

less_preferred_words=(
    "eim"  # Full name "Edge Infrastructure Manager" is preferred.
    "fm"   # Lots of false alarm. It's OK as long as it is not referring to fleet manager.
    "itep" # It is allowed to reference internal Jira tickets, but should be avoided elsewhere.
    "orch-deploy" # It should be edge-managability-framework
)

ignore_globs=(
    "*.bin"
    "*.dll"
    "*.exe"
    "*.o"
    "*.so"
    "*.crt"
)

ignore_dirs=(
    ".git"
    "lint-forbidden-words"
    ".github"
)

error=0
content_total_forbidden_matches=0
name_total_forbidden_matches=0
content_total_less_preferred_matches=0
name_total_less_preferred_matches=0

# Build the grep exclude options
exclude_opts=()
for glob in "${ignore_globs[@]}"; do
    exclude_opts+=(--exclude="$glob")
done
for dir in "${ignore_dirs[@]}"; do
    exclude_opts+=(--exclude-dir="$dir")
done

check_words() {
    local is_forbidden=$1
    shift
    local words=("$@")
    for word in "${words[@]}"; do
        matches=$(grep -r -w -i -n "${exclude_opts[@]}" "$word" . 2>/dev/null || true)
        match_count=$(echo "$matches" | wc -l)
        if [ "$match_count" -gt 0 ] && [ -n "$matches" ]; then
            echo ""
            echo "Found $match_count $( [ "$is_forbidden" = true ] && echo "forbidden" || echo "less preferred" ) words: $word"
            echo "$matches"
            [ "$is_forbidden" = true ] && error=1
            if [ "$is_forbidden" = true ]; then
                content_total_forbidden_matches=$((content_total_forbidden_matches + match_count))
            else
                content_total_less_preferred_matches=$((content_total_less_preferred_matches + match_count))
            fi
        fi

        name_matches=$(find . -path ./.git -prune -o -regex ".*$word.*" -print | grep -w -i "$word" || true)
        name_match_count=$(echo "$name_matches" | wc -l)
        if [ "$name_match_count" -gt 0 ] && [ -n "$name_matches" ]; then
            echo ""
            echo "Found $name_match_count $( [ "$is_forbidden" = true ] && echo "forbidden" || echo "less preferred" ) filename: $word"
            echo "$name_matches"
            [ "$is_forbidden" = true ] && error=1
            if [ "$is_forbidden" = true ]; then
                name_total_forbidden_matches=$((name_total_forbidden_matches + name_match_count))
            else
                name_total_less_preferred_matches=$((name_total_less_preferred_matches + name_match_count))
            fi
        fi
    done
}

check_words true "${forbidden_words[@]}"
check_words false "${less_preferred_words[@]}"

echo ""
echo "Total forbidden words: $content_total_forbidden_matches"
echo "Total forbidden filename: $name_total_forbidden_matches"
echo "Total less preferred words: $content_total_less_preferred_matches"
echo "Total less preferred filename: $name_total_less_preferred_matches"

if [ "$fail_on_match" = "true" ]; then
    exit $error
else
    exit 0
fi
