#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
set -o pipefail

WORKSPACE=${WORKSPACE:-$(pwd)}
HELM_TARGETS="attestation-manager attestation-verifier trustagent trusted-workload"

# Check if helm is installed
command -v helm >/dev/null 2>&1 || { echo "ERROR: helm not found, please install it" >&2; exit 1; }

#remove any existing helm dependency files and lock files
cleanup() {
    echo "INFO: Cleaning up Helm dependency files..."
    find "${WORKSPACE}" \( -name Chart.lock -o -name "*.tgz" \) -print0 | while IFS= read -r -d '' file; do
        rm -rf "${file}"
    done
    find "${WORKSPACE}" -type d -name charts -print0 | while IFS= read -r -d '' dir; do
        [ ! "$(ls -A "$dir")" ] && rm -rf "$dir"
    done
    exit 0
}

[[ "$1" == "clean" ]] && cleanup

chart_dir=""

# Update dependencies for all subcharts and lint
find "${WORKSPACE}" -name Chart.yaml -print0 | while IFS= read -r -d '' chart; do
    chart_dir=$(dirname "$chart")
    echo "INFO: Updating dependencies for $chart_dir"
    helm dependency update "$chart_dir"
    helm lint "$chart_dir" --strict
    echo ""
done

# remove any existing helm dependency files and lock files
cleanup