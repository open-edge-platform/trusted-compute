#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

DEVICE_INJECTOR_BUILD_DIR="${PWD}"
NRI_REPO_URL="https://github.com/containerd/nri.git"
NRI_REPO_BRANCH="v0.9.0"
NRI_DIR="${DEVICE_INJECTOR_BUILD_DIR}/nri"

DOCKER_IMAGE="ubuntu:24.04"

echo "INFO: Starting device-injector build"

# Remove existing nri directory if it exists
if [ -d "${NRI_DIR}" ]; then
    echo "INFO: Removing existing nri directory"
    rm -rf "${NRI_DIR}"
fi

echo "INFO: Cloning NRI repo"
git clone --single-branch --branch "${NRI_REPO_BRANCH}" "${NRI_REPO_URL}" "${NRI_DIR}"

# Create build script for inside the container
cat > "${DEVICE_INJECTOR_BUILD_DIR}/build_in_container.sh" <<'EOF'
#!/bin/bash
set -euo pipefail
apt-get update
apt-get install -y wget
wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
export PATH="/usr/local/go/bin:${PATH}"
cd /workspace/nri/plugins/device-injector
go build -o /workspace/10-device-injector device-injector.go
chmod +x /workspace/10-device-injector
EOF

chmod +x "${DEVICE_INJECTOR_BUILD_DIR}/build_in_container.sh"

# Run the build inside a Docker container
docker run --rm \
    -v "${DEVICE_INJECTOR_BUILD_DIR}:/workspace" \
    ubuntu:24.04 \
    /bin/bash /workspace/build_in_container.sh

echo "INFO: Device injector binary is in $DEVICE_INJECTOR_BUILD_DIR"

# Cleanup: remove cloned repo and build script
rm -rf "${NRI_DIR}"
rm -f "${DEVICE_INJECTOR_BUILD_DIR}/build_in_container.sh"
