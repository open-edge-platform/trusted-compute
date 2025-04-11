#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

apt update
apt install  -o Acquire::Retries=3 -y --no-install-recommends git qemu-utils parted udev gcc ca-certificates build-essential

BUILD_DIR="/trusted-vm/build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
TVM_AGENT_DIR="/trusted-vm/tvm-agent"
TRUSTED_VM_IMAGE="trusted-vm.img"

# edge_microvisor image
EDGE_MICROVISOR_IMAGE_NAME=""
EDGE_MICROVISOR_DIR=${BUILD_DIR}/microvisor_src
EDGE_MICROVISOR_IMAGE_DIR=${EDGE_MICROVISOR_DIR}/out/images/trusted-compute-os

# Kata Containers
KATA_CONTAINERS_SRC_DIR=${BUILD_DIR}/kata_src
IMAGE_BUILD_SCRIPT_DIR="${KATA_CONTAINERS_SRC_DIR}/tools/osbuilder/image-builder"

mkdir -p "${ROOTFS_DIR}"

# Function to extract edge_microvisor image rootfs
extract_edge_microvisor_image_rootfs() {
    EDGE_MICROVISOR_IMAGE_NAME=$(find ${EDGE_MICROVISOR_IMAGE_DIR} -type f -name "Trusted-Compute*.tar.gz")
    if [ $(echo "${EDGE_MICROVISOR_IMAGE_NAME}" | wc -l) -ne 1 ]; then
        echo "ERROR: Expected exactly one rootfs tar.gz file, but found multiple or none."
        exit 1
    fi
    tar -xf "${EDGE_MICROVISOR_IMAGE_NAME}" -C "${ROOTFS_DIR}"
    EDGE_MICROVISOR_IMAGE_NAME=$(basename ${EDGE_MICROVISOR_IMAGE_NAME})
    echo "INFO: edge_microvisor image rootfs extracted successfully in ${ROOTFS_DIR}"

    #copy the kernel from the rootfs
    KERNEL_NAME=$(find "${ROOTFS_DIR}/boot" -type f -name "vmlinuz-*")
    if [ $(echo "${KERNEL_NAME}" | wc -l) -ne 1 ]; then
        echo "WARNING: Expected exactly one kernel Image, but found multiple or none. Skipping kernel copy."
        exit 1
    fi
    cp "${KERNEL_NAME}" "${BUILD_DIR}"
    chmod 644 "${BUILD_DIR}/$(basename ${KERNEL_NAME})"
    echo "INFO: Kernel copied successfully to ${BUILD_DIR}"

    #copy kernel config from the rootfs
    KERNEL_CONFIG=$(find "${ROOTFS_DIR}/boot" -type f -name "config-*")
    if [ $(echo "${KERNEL_CONFIG}" | wc -l) -ne 1 ]; then
        echo "WARNING: Expected exactly one kernel config file, but found multiple or none. Skipping kernel config copy."
        exit 1
    fi
    cp "${KERNEL_CONFIG}" "${BUILD_DIR}"
    chmod 644 "${BUILD_DIR}/$(basename ${KERNEL_CONFIG})"
    echo "INFO: Kernel config copied successfully to ${BUILD_DIR}"

    #remove boot directory from rootfs
    rm -rf "${ROOTFS_DIR}/boot"

}

#install tvm-agent and service files
install_tvm_agent() {
    echo "INFO: Installing Kata Agent in rootfs"
    install -o root -g root -m 0550 -t "${ROOTFS_DIR}/usr/bin" "${TVM_AGENT_DIR}/output/kata-agent"
    install -o root -g root -m 0440 ${TVM_AGENT_DIR}/output/kata-agent.service "${ROOTFS_DIR}/usr/lib/systemd/system/"
    install -o root -g root -m 0440 "${TVM_AGENT_DIR}/output/kata-containers.target" "${ROOTFS_DIR}/usr/lib/systemd/system/"
}

#build Trusted vm image from rootfs
build_trusted_vm_image() {
    echo "INFO: Starting Trusted VM image build"
    pushd "${IMAGE_BUILD_SCRIPT_DIR}"
    # Run the image builder script
    if ! IMAGE="${TRUSTED_VM_IMAGE}" bash ${DEBUG:+-x} ./image_builder.sh "${ROOTFS_DIR}"; then
        echo "ERROR: Failed to build Trusted VM image"
        exit 1
    fi
    #check if image generated successfully
    if [ ! -f "${TRUSTED_VM_IMAGE}" ]; then
        echo "ERROR: ${TRUSTED_VM_IMAGE} image not generated"
        echo "ERROR: Failed to build Trusted VM image"
        exit 1
    fi
    popd
}

#copy the image to the output directory
copy_tc_image(){
    cp "${IMAGE_BUILD_SCRIPT_DIR}/${TRUSTED_VM_IMAGE}" "${BUILD_DIR}/${TRUSTED_VM_IMAGE}"
}

# main function
################
extract_edge_microvisor_image_rootfs
install_tvm_agent
build_trusted_vm_image
copy_tc_image
