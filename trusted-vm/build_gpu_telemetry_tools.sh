#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Builds GPU telemetry tools from source.
# Runs inside a docker.io/library/rust:1.88 container.
# Binaries are copied to the output directory (mounted volume):
#   /trusted-vm/gpu-telemetry/binaries  — qmassa, qmmd
#

set -euo pipefail

QMMD_VERSION="0.2.0"
QMMD_COMMIT="590302e8353d9205c40bd9522e93949173e3dae9"
QMASSA_VERSION="2.1.0"
QMASSA_COMMIT="590302e8353d9205c40bd9522e93949173e3dae9"
GPU_OUT_DIR="/trusted-vm/gpu-telemetry/binaries"

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y --no-install-recommends ca-certificates libudev-dev && apt-get clean && rm -rf /var/lib/apt/lists/*
export PATH="$HOME/.cargo/bin:$PATH"

# --------------------------
# GPU tools: qmmd and qmassa
# --------------------------
echo "INFO: Building qmmd v${QMMD_VERSION} (commit: ${QMMD_COMMIT})"
cargo install --locked --force --git https://github.com/ulissesf/qmassa --rev "${QMMD_COMMIT}" qmmd
command -v qmmd > /dev/null || { echo "ERROR: qmmd binary not found in PATH"; exit 1; }
echo "INFO: qmmd installed: $(qmmd --version)"

echo "INFO: Building qmassa v${QMASSA_VERSION} (commit: ${QMASSA_COMMIT})"
cargo install --locked --force --git https://github.com/ulissesf/qmassa --rev "${QMASSA_COMMIT}" qmassa
command -v qmassa > /dev/null || { echo "ERROR: qmassa binary not found in PATH"; exit 1; }
echo "INFO: qmassa installed: $(qmassa --version)"

mkdir -p "${GPU_OUT_DIR}"
cp /usr/local/cargo/bin/qmmd   "${GPU_OUT_DIR}/qmmd"
cp /usr/local/cargo/bin/qmassa "${GPU_OUT_DIR}/qmassa"
echo "INFO: GPU binaries copied to ${GPU_OUT_DIR}"
ls -lh "${GPU_OUT_DIR}"
