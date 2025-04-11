#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

TVM_AGENT_BUILD_DIR="${PWD}"
KATA_CONTAINER_DIR="${TVM_AGENT_BUILD_DIR}/kata-containers"

KATA_CONTAINER_GIT_URL="https://github.com/kata-containers/kata-containers.git"
KATA_CONTAINER_GIT_BRANCH="3.15.0"

DOCKER_IMAGE="ubuntu:24.04"
TVM_AGENT_CLEAN_AFTER_BUILD="yes"

# Function to clean up after build
cleanup() {
    if [ "${TVM_AGENT_CLEAN_AFTER_BUILD}" == "yes" ]; then
        echo "INFO: Cleaning up after build"
        if ! rm -rf "${KATA_CONTAINER_DIR}" 2>/dev/null; then
            echo "INFO: Permission denied, trying with sudo"
            sudo rm -rf "${KATA_CONTAINER_DIR}"
        fi
        echo "INFO: Cleanup completed"
    fi
}

# Trap to ensure cleanup is called on script exit
if [ "${TVM_AGENT_CLEAN_AFTER_BUILD}" == "yes" ]; then
    trap cleanup EXIT
fi

echo "INFO: Starting kata-agent build"

# Remove existing kata-container directory if it exists
if [ -d "${KATA_CONTAINER_DIR}" ]; then
    echo "INFO: Removing existing kata-container directory"
    if ! rm -rf "${KATA_CONTAINER_DIR}" 2>/dev/null; then
        echo "INFO: Permission denied, trying with sudo"
        sudo rm -rf "${KATA_CONTAINER_DIR}"
    fi
fi

echo "INFO: Cloning kata-containers repo"

# Clone the kata-containers repository
if ! git clone --single-branch --branch "${KATA_CONTAINER_GIT_BRANCH}" "${KATA_CONTAINER_GIT_URL}" "${KATA_CONTAINER_DIR}"; then
    echo "ERROR: Failed to clone kata-containers repo"
    exit 1
fi

# Run the build inside a Docker container
docker run --rm \
    -v "${TVM_AGENT_BUILD_DIR}:/tvm_agent" \
    ubuntu:24.04 \
    /bin/bash /tvm_agent/tvm_agent_inside_container.sh

# create a directory to store the kata-agent binary
mkdir -p "${TVM_AGENT_BUILD_DIR}/output"

#copy kata-agent binary and service files to the current directory
echo "INFO: Copying kata-agent binary and service to output directory"
cp "${KATA_CONTAINER_DIR}/src/agent/target/x86_64-unknown-linux-musl/release/kata-agent" "${TVM_AGENT_BUILD_DIR}/output"
cp "${KATA_CONTAINER_DIR}/src/agent/kata-agent.service" "${TVM_AGENT_BUILD_DIR}/output"
cp "${KATA_CONTAINER_DIR}/src/agent/kata-containers.target" "${TVM_AGENT_BUILD_DIR}/output"

echo "INFO: Completed kata-agent build successfully"
