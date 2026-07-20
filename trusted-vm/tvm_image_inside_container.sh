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
GPU_TELEMETRY_DIR="/trusted-vm/gpu-telemetry"
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

#install guest OCI hooks
install_guest_hooks() {
    echo "INFO: Installing guest OCI hooks in rootfs"
    local hooks_src="/trusted-vm/hooks"
    local hooks_dest="${ROOTFS_DIR}/usr/share/oci/hooks"
    local gpu_hook="${hooks_src}/prestart/scan-for-gpu.sh"

    [[ -f "${gpu_hook}" ]] || { echo "ERROR: Guest hook not found: ${gpu_hook}"; exit 1; }

    mkdir -p "${hooks_dest}/prestart"
    install -o root -g root -m 0550 "${gpu_hook}" "${hooks_dest}/prestart/"
    echo "INFO: Guest hooks installed successfully"
}

# Install GPU telemetry binaries and config into the rootfs.
install_gpu_telemetry() {
    echo "INFO: Installing GPU telemetry agent in rootfs"
    local bin_src="${GPU_TELEMETRY_DIR}/binaries"
    local files_src="${GPU_TELEMETRY_DIR}/files"

    [[ -d "${bin_src}" ]]        || { echo "ERROR: ${bin_src} not found"; exit 1; }
    [[ -x "${bin_src}/qmassa" ]] || { echo "ERROR: qmassa not found in ${bin_src}"; exit 1; }
    [[ -x "${bin_src}/qmmd" ]]   || { echo "ERROR: qmmd not found in ${bin_src}"; exit 1; }
    [[ -x "${bin_src}/jq" ]]     || { echo "ERROR: jq not found in ${bin_src}"; exit 1; }
    [[ -d "${files_src}" ]]      || { echo "ERROR: ${files_src} not found"; exit 1; }

    echo "INFO: GPU telemetry tools ready in ${bin_src}"

    mkdir -p "${ROOTFS_DIR}/etc/gpu-telemetry" \
             "${ROOTFS_DIR}/etc/udev/rules.d" \
             "${ROOTFS_DIR}/usr/local/bin" \
             "${ROOTFS_DIR}/usr/lib/systemd/system/kata-containers.target.wants"
    install -o root -g root -m 0550 "${bin_src}/qmassa" "${ROOTFS_DIR}/usr/local/bin/qmassa"
    install -o root -g root -m 0550 "${bin_src}/qmmd"   "${ROOTFS_DIR}/usr/local/bin/qmmd"
    install -o root -g root -m 0550 "${bin_src}/jq"     "${ROOTFS_DIR}/usr/local/bin/jq"
    install -o root -g root -m 0550 "${files_src}/gpu-telemetry-agent.sh" "${ROOTFS_DIR}/usr/local/bin/gpu-telemetry-agent.sh"
    install -o root -g root -m 0440 "${files_src}/gpu-telemetry-guest.env" "${ROOTFS_DIR}/etc/gpu-telemetry/gpu-telemetry.env"
    install -o root -g root -m 0440 "${files_src}/gpu-telemetry-guest.service" "${ROOTFS_DIR}/usr/lib/systemd/system/gpu-telemetry.service"
    ln -sf ../gpu-telemetry.service "${ROOTFS_DIR}/usr/lib/systemd/system/kata-containers.target.wants/gpu-telemetry.service"
    install -o root -g root -m 0444 "${files_src}/90-gpu-telemetry.rules" "${ROOTFS_DIR}/etc/udev/rules.d/90-gpu-telemetry.rules"

    echo "INFO: GPU telemetry installed successfully"
    echo "INFO: Cleaning up GPU telemetry binaries"
    rm -rf "${bin_src}"
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
install_guest_hooks
install_gpu_telemetry
build_trusted_vm_image
copy_tc_image
