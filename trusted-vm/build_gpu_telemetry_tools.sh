#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Builds qmassa (static musl binary) from source and downloads static jq.
# Output: /trusted-vm/gpu-telemetry/binaries/{qmassa,jq}
# Runs inside the TVM build container (ubuntu:24.04).
#

set -euo pipefail

QMASSA_VERSION="2.1.0"
JQ_VERSION="1.7.1"
OUT_DIR="/trusted-vm/gpu-telemetry/binaries"

mkdir -p "${OUT_DIR}"

echo "INFO: Downloading jq ${JQ_VERSION}"
apt-get update -qq && apt-get install -y --no-install-recommends curl ca-certificates libudev-dev musl-tools
curl -fsSL --retry 3 \
    "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64" \
    -o "${OUT_DIR}/jq"
chmod +x "${OUT_DIR}/jq"
echo "INFO: jq downloaded: $(${OUT_DIR}/jq --version)"

echo "INFO: Building qmassa v${QMASSA_VERSION}"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal
# shellcheck source=/dev/null
source "${HOME}/.cargo/env"
rustup target add x86_64-unknown-linux-musl
cargo install --locked \
    --target x86_64-unknown-linux-musl \
    --git https://github.com/ulissesf/qmassa \
    --tag "qmassa-v${QMASSA_VERSION}" \
    qmassa
cp "${CARGO_HOME:-${HOME}/.cargo}/bin/qmassa" "${OUT_DIR}/qmassa"
strip "${OUT_DIR}/qmassa"
echo "INFO: qmassa built: $(${OUT_DIR}/qmassa --version 2>&1 || true)"

echo "INFO: GPU telemetry tools ready in ${OUT_DIR}"
ls -lh "${OUT_DIR}"
