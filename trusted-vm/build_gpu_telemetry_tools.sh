#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#
# Builds qmassa and qmmd from source.
# Runs inside a docker.io/library/rust:1.88 container.
# Binaries are copied to /trusted-vm/gpu-telemetry/binaries (mounted volume).
#

set -euo pipefail

QMMD_VERSION="0.2.0"
QMASSA_VERSION="2.1.0"
OUT_DIR="/trusted-vm/gpu-telemetry/binaries"

DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y --no-install-recommends ca-certificates libudev-dev && apt-get clean && rm -rf /var/lib/apt/lists/*
export PATH="$HOME/.cargo/bin:$PATH"

echo "INFO: Building qmmd v${QMMD_VERSION} from GitHub"
cargo install --locked --force --git https://github.com/ulissesf/qmassa --tag qmmd-v${QMMD_VERSION} qmmd
command -v qmmd > /dev/null || { echo "ERROR: qmmd binary not found in PATH"; exit 1; }
echo "INFO: qmmd installed: $(qmmd --version)"

echo "INFO: Building qmassa v${QMASSA_VERSION} from GitHub"
cargo install --locked --force --git https://github.com/ulissesf/qmassa --tag qmassa-v${QMASSA_VERSION} qmassa
command -v qmassa > /dev/null || { echo "ERROR: qmassa binary not found in PATH"; exit 1; }
echo "INFO: qmassa installed: $(qmassa --version)"

# Copy binaries to output directory (mounted volume)
mkdir -p "${OUT_DIR}"
cp /usr/local/cargo/bin/qmmd "${OUT_DIR}/qmmd"
cp /usr/local/cargo/bin/qmassa "${OUT_DIR}/qmassa"
echo "INFO: Binaries copied to ${OUT_DIR}"
ls -lh "${OUT_DIR}"
