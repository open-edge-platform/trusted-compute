#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

# Update package list and install dependencies
echo "INFO: Updating package list and installing dependencies"
apt update
apt install -o Acquire::Retries=3 -y --no-install-recommends make gcc g++ curl wget ca-certificates \
    libc6-dev musl-tools libseccomp-dev libclang-dev

# Update CA certificates
echo "INFO: Updating CA certificates"
update-ca-certificates

TVM_AGENT_BUILD_DIR=/tvm_agent
KATA_CONTAINER_DIR="${TVM_AGENT_BUILD_DIR}/kata-containers"

# Install yq
echo "INFO: Getting yq version from ci/install_yq.sh"
YQ_VERSION=$(grep -oP 'local yq_version=\Kv[0-9]+\.[0-9]+\.[0-9]+' "${KATA_CONTAINER_DIR}/ci/install_yq.sh")
if [ -z "${YQ_VERSION}" ]; then
    echo "ERROR: Failed to get yq version from ci/install_yq.sh"
    YQ_VERSION=v4.44.5
    echo "INFO: Installing default yq version : ${YQ_VERSION}"
else
    echo "INFO: Installing yq version from ci/install_yq.sh : ${YQ_VERSION}"
fi
wget -q https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64 -O /usr/local/bin/yq
chmod +x /usr/local/bin/yq

# Install Go
echo "INFO: Getting Go version from versions.yaml"
GO_VERSION=$(yq e '.languages.golang.version' "${KATA_CONTAINER_DIR}/versions.yaml")
if [ -z "${GO_VERSION}" ]; then
    echo "ERROR: Failed to get Go version from versions.yaml"
    GO_VERSION=1.22.11
    echo "INFO: Installing default Go version : ${GO_VERSION}"
else
    echo "INFO: Installing Go version from versions.yaml : ${GO_VERSION}"
fi
wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz || { echo "ERROR: Failed to download Go"; exit 1; }
tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

# Install Rust
echo "INFO: Getting Rust version from versoions.yaml"
RUST_VERSION=$(yq e '.languages.rust.version' "${KATA_CONTAINER_DIR}/versions.yaml")
if [ -z "${RUST_VERSION}" ]; then
    echo "ERROR: Failed to get Rust version from versions.yaml"
    RUST_VERSION=1.80.0
    echo "INFO: Installing default Rust version : ${RUST_VERSION}"
else
    echo "INFO: Installing Rust version from versions.yaml : ${RUST_VERSION}"
fi
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_VERSION} \
    || { echo "ERROR: Failed to install Rust"; exit 1; }
source $HOME/.cargo/env

#For building the agent with seccomp support using musl, set the environment variables for the libseccomp
#if the compilation fails when the agent tries to link the libseccomp library statically against musl, 
#we need to build libseccomp manually and set the environment variables accordingly.
echo "INFO: Building libseccomp to link the libseccomp library statically against musl"
export libseccomp_install_dir=$(mktemp -d -t libseccomp.XXXXXXXXXX)
export gperf_install_dir=$(mktemp -d -t gperf.XXXXXXXXXX)
bash ${KATA_CONTAINER_DIR}/ci/install_libseccomp.sh "${libseccomp_install_dir}" "${gperf_install_dir}"
export LIBSECCOMP_LINK_TYPE=static 
export LIBSECCOMP_LIB_PATH="${libseccomp_install_dir}/lib"

#Set LIBCLANG_PATH
LIBCLANG_PATH=$(find /usr -name "libclang.so*" | head -n 1 | xargs dirname)
echo "INFO: Setting LIBCLANG_PATH to ${LIBCLANG_PATH}"
export LIBCLANG_PATH="${LIBCLANG_PATH}"

#The agent is built with a statically linked musl.
arch=$(uname -m)
rustup target add "${arch}-unknown-linux-musl"
ln -s /usr/bin/g++ /bin/musl-g++

echo "INFO: Building kata-agent"
make -C ${KATA_CONTAINER_DIR}/src/agent

#Create kata-agent.service
make -C ${KATA_CONTAINER_DIR}/src/agent kata-agent.service