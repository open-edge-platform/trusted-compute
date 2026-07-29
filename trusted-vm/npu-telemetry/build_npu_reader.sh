#!/bin/bash
#
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Builds the npu-reader binary from Python sources using PyInstaller.
# Runs inside a docker.io/library/python:3.11-slim container.
#
# Downloads npu_reader.py and npu_monitor_tool.py from edge-ai-libraries at a
# pinned commit, applies minimal TC-specific patches, then bundles them into a
# single standalone executable that needs no Python runtime in the guest VM.
#
# Upstream source:
#   https://github.com/open-edge-platform/edge-ai-libraries
#   Path: microservices/metrics-manager/scripts/
#
# To update, change EDGE_AI_LIBS_COMMIT to the desired commit SHA and rebuild.

set -euo pipefail

EDGE_AI_LIBS_COMMIT="1dec797e67b0bf61b723d8bb3157cb1d00714298"
EDGE_AI_LIBS_TAG="2026.2-20260728"
EDGE_AI_LIBS_RAW="https://raw.githubusercontent.com/open-edge-platform/edge-ai-libraries"
SCRIPTS_PATH="microservices/metrics-manager/scripts"

NPU_OUT_DIR="/trusted-vm/npu-telemetry/binaries"
BUILD_DIR="/tmp/npu-reader-build"

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && apt-get clean && rm -rf /var/lib/apt/lists/*

pip install --no-cache-dir pyinstaller

mkdir -p "${BUILD_DIR}" "${NPU_OUT_DIR}"

# Download both scripts from edge-ai-libraries at pinned commit
echo "INFO: Downloading npu_reader.py and npu_monitor_tool.py @ ${EDGE_AI_LIBS_TAG} (${EDGE_AI_LIBS_COMMIT})"
curl -fsSL "${EDGE_AI_LIBS_RAW}/${EDGE_AI_LIBS_COMMIT}/${SCRIPTS_PATH}/npu_reader.py" -o "${BUILD_DIR}/npu_reader.py"
curl -fsSL "${EDGE_AI_LIBS_RAW}/${EDGE_AI_LIBS_COMMIT}/${SCRIPTS_PATH}/npu_monitor_tool.py" -o "${BUILD_DIR}/npu_monitor_tool.py"

# Apply minimal TC-specific patches to npu_reader.py:
#   1. Remove sys.path.insert('/app') — PyInstaller bundles npu_monitor_tool
#   2. Replace FileHandler(/app/...) with StreamHandler(stderr) — logs go to
#      the systemd journal via npu-telemetry-agent.sh; no file size concern
#   3. Replace idle_forever() body with sys.exit(1) so systemd can restart
#      the service when the NPU is hotplugged after boot
#   4. Accept METRICS_HOSTNAME env var (our convention) in addition to
#      METRICS_MANAGER_HOSTNAME (upstream convention)
#   5. Make INTERVAL_S configurable via NPU_INTERVAL_MS env var
echo "INFO: Patching npu_reader.py for TC guest VM environment"
cd "${BUILD_DIR}"
python3 - << 'PATCH_EOF'
import re, sys

src = open("npu_reader.py").read()

# 1. Remove sys.path.insert('/app')
src = src.replace("sys.path.insert(0, '/app')\n", "")

# 2. Replace file-based logging with stderr so logs reach the systemd journal.
#    Removes DEBUG_LOG, file_handler, and the original logger setup block,
#    replacing them with a single basicConfig(stream=sys.stderr) call.
src = re.sub(
    r'DEBUG_LOG = "[^\n]+"\n\n'
    r'file_handler = logging\.FileHandler\(DEBUG_LOG\)\n'
    r'file_handler\.setFormatter\(\n'
    r'    logging\.Formatter\(\n'
    r'        fmt=[^\n]+\n'
    r'        datefmt=[^\n]+\n'
    r'    \)\n'
    r'\)\n'
    r'logger = logging\.getLogger\(\)\n'
    r'logger\.setLevel\(logging\.INFO\)\n'
    r'logger\.handlers = \[file_handler\]\n',
    'logging.basicConfig(stream=sys.stderr, level=logging.INFO,\n'
    '    format="%(asctime)s %(levelname)s %(name)s %(message)s",\n'
    '    datefmt="%Y-%m-%dT%H:%M:%SZ")\n'
    'logger = logging.getLogger()\n',
    src,
    flags=re.DOTALL
)

# 3. Replace idle_forever body: sleep-forever -> sys.exit(1)
src = re.sub(
    r'(def idle_forever\(reason: str\) -> None:\n)'
    r'    """.*?"""\n'
    r'    logger\.warning\("NPU reader entering idle mode: %s", reason\)\n'
    r'    while True:\n'
    r'        time\.sleep\(IDLE_SLEEP_S\)\n',
    r'\1    print(f"[npu-reader] {reason}", file=sys.stderr)\n    sys.exit(1)\n',
    src,
    flags=re.DOTALL
)

# 4. Accept METRICS_HOSTNAME (TC convention) with fallback to upstream name
src = src.replace(
    'HOSTNAME = os.environ.get("METRICS_MANAGER_HOSTNAME") or os.uname()[1]',
    'HOSTNAME = os.environ.get("METRICS_HOSTNAME") or os.environ.get("METRICS_MANAGER_HOSTNAME") or os.uname()[1]'
)

# 5. Make interval configurable via NPU_INTERVAL_MS
src = src.replace(
    "INTERVAL_S = 1.0",
    'INTERVAL_S = int(os.environ.get("NPU_INTERVAL_MS", "1000")) / 1000.0'
)

open("npu_reader.py", "w").write(src)
print("Patches applied successfully")
PATCH_EOF

# Build a single-file standalone executable
echo "INFO: Running PyInstaller to produce npu-reader"
pyinstaller \
    --onefile \
    --name npu-reader \
    --hidden-import npu_monitor_tool \
    npu_reader.py

cp "${BUILD_DIR}/dist/npu-reader" "${NPU_OUT_DIR}/npu-reader"
echo "INFO: npu-reader binary built successfully"
ls -lh "${NPU_OUT_DIR}/npu-reader"
