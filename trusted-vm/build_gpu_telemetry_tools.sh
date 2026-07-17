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
QMASSA_REV="590302e8353d9205c40bd9522e93949173e3dae9"
JQ_VERSION="1.7.1"
JQ_SHA256="5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5"
# Pin the Rust toolchain for reproducible builds.
RUST_TOOLCHAIN="1.88.0"
OUT_DIR="/trusted-vm/gpu-telemetry/binaries"

mkdir -p "${OUT_DIR}"

echo "INFO: Downloading jq ${JQ_VERSION}"
apt-get update -qq && apt-get install -y --no-install-recommends binutils curl ca-certificates libudev-dev musl-tools
curl -fsSL --retry 3 \
    "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/jq-linux-amd64" \
    -o "${OUT_DIR}/jq"
echo "${JQ_SHA256}  ${OUT_DIR}/jq" | sha256sum -c -
chmod +x "${OUT_DIR}/jq"
echo "INFO: jq downloaded: $(${OUT_DIR}/jq --version)"

echo "INFO: Building qmassa v${QMASSA_VERSION} with Rust ${RUST_TOOLCHAIN}"
apt-get install -y --no-install-recommends rustup
mkdir -p "${CARGO_HOME:-${HOME}/.cargo}/bin"
ln -sf "$(command -v rustup)" "${CARGO_HOME:-${HOME}/.cargo}/bin/rustup"
rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal
rustup target add --toolchain "${RUST_TOOLCHAIN}" x86_64-unknown-linux-musl
rustup run "${RUST_TOOLCHAIN}" cargo install --locked \
    --target x86_64-unknown-linux-musl \
    --git https://github.com/ulissesf/qmassa \
    --rev "${QMASSA_REV}" \
    qmassa
cp "${CARGO_HOME:-${HOME}/.cargo}/bin/qmassa" "${OUT_DIR}/qmassa"
strip "${OUT_DIR}/qmassa"
echo "INFO: qmassa built: $(${OUT_DIR}/qmassa --version 2>&1 || true)"

echo "INFO: GPU telemetry tools ready in ${OUT_DIR}"
ls -lh "${OUT_DIR}"
