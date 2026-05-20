#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

KATA_BUILD_DIR="${PWD}"
KATA_REPO_URL="https://github.com/kata-containers/kata-containers.git"
KATA_REPO_TAG=$(yq '.kata-containers.version' version.yaml)
KATA_DIR="${KATA_BUILD_DIR}/kata-containers"
PATCH_FILE="${KATA_BUILD_DIR}/increase_prefetch_memory_size.patch"

echo "INFO: Starting kata-containers binary build"

# Remove existing kata-containers directory if it exists
if [ -d "${KATA_DIR}" ]; then
    echo "INFO: Removing existing kata-containers directory"
    rm -rf "${KATA_DIR}"
fi

echo "INFO: Cloning kata-containers repo"
git clone --single-branch --branch "${KATA_REPO_TAG}" "${KATA_REPO_URL}" "${KATA_DIR}"

#apply patch
pushd "${KATA_DIR}"
git apply "${PATCH_FILE}"
popd

GO_VERSION=$(yq '.languages.golang.version' "${KATA_DIR}/versions.yaml" 2>/dev/null || true)
[[ "${GO_VERSION}" == "null" || -z "${GO_VERSION}" ]] && GO_VERSION="1.25.9"
echo "INFO: Using Go version ${GO_VERSION}"

# Create build script for inside the container
cat > "${KATA_BUILD_DIR}/build_kata_in_container.sh" <<EOF
#!/bin/bash
set -euo pipefail
apt-get update
apt-get install -y wget make git build-essential curl
wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
export PATH="/usr/local/go/bin:${PATH}"
export GOPATH="${HOME}/go"
git config --global --add safe.directory /workspace/kata-containers
cd /workspace/kata-containers
make -C src/runtime
cp src/runtime/kata-runtime /workspace/
cp src/runtime/containerd-shim-kata-v2 /workspace/
EOF

chmod +x "${KATA_BUILD_DIR}/build_kata_in_container.sh"

# Run the build inside a Docker container
docker run --rm \
    -e GO_VERSION="${GO_VERSION}" \
    -v "${KATA_BUILD_DIR}:/workspace" \
    ubuntu:24.04 \
    /bin/bash /workspace/build_kata_in_container.sh

echo "INFO: Kata binaries are in $KATA_BUILD_DIR"

# Cleanup: remove cloned repo and build script
rm -rf "${KATA_DIR}"
rm -f "${KATA_BUILD_DIR}/build_kata_in_container.sh"
