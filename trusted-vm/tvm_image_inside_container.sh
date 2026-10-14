#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

apt update
apt install -o Acquire::Retries=3 -y --no-install-recommends \
    git qemu-utils parted udev gcc ca-certificates build-essential curl \
    mmdebstrap debian-archive-keyring erofs-utils musl-tools xz-utils zstd makedev sudo gnupg golang-go

# Ubuntu's bundled debian-archive-keyring predates Debian 13's signing keys;
# refresh it from Debian's own archive (TLS-verified) so mmdebstrap can
# authenticate the trixie Release file.
echo "deb https://deb.debian.org/debian trixie main" > /etc/apt/sources.list.d/debian-keyring-bootstrap.list
apt-get update -o Acquire::AllowInsecureRepositories=true
apt-get install -y --allow-unauthenticated --reinstall debian-archive-keyring
rm -f /etc/apt/sources.list.d/debian-keyring-bootstrap.list
apt-get update

# Build yq/oras from source via the Go module proxy, pinned to the exact
# versions kata's own install_yq.sh/install_oras.sh expect. This avoids both
# a host-binary dependency (bind-mounts break on systems without them) and
# kata's upstream scripts, which fetch prebuilt binaries from GitHub release
# assets.
GOBIN=/usr/local/bin go install github.com/mikefarah/yq/v4@v4.44.5
GOBIN=/usr/local/bin go install oras.land/oras/cmd/oras@v1.2.0

BUILD_DIR="/trusted-vm/build"
ROOTFS_DIR="${BUILD_DIR}/rootfs"
KATA_CONTAINERS_SRC_DIR="${BUILD_DIR}/kata_src"
GPU_TELEMETRY_DIR="/trusted-vm/gpu-telemetry"
NPU_TELEMETRY_DIR="/trusted-vm/npu-telemetry"

# kata_src is cloned on the host (non-root); silence git's ownership check
# so version-detection commands running as root here don't fail/go empty.
git config --global --add safe.directory "${KATA_CONTAINERS_SRC_DIR}"

# base:    minimal guest rootfs only
# gpu-npu: base + GPU/NPU telemetry agents and the GPU prestart hook
# custom:  gpu-npu + extra packages from CUSTOM_EXTRA_PKGS (e.g. debugging tools)
IMAGE_VARIANT="${IMAGE_VARIANT:-base}"
case "${IMAGE_VARIANT}" in
    base|gpu-npu|custom) ;;
    *) echo "ERROR: IMAGE_VARIANT must be one of: base, gpu-npu, custom" >&2; exit 1 ;;
esac
CUSTOM_EXTRA_PKGS="${CUSTOM_EXTRA_PKGS:-strace gdb pciutils procps iproute2}"
if [[ "${IMAGE_VARIANT}" == "base" ]]; then
    TRUSTED_VM_IMAGE="trusted-vm.img"
else
    TRUSTED_VM_IMAGE="trusted-vm-${IMAGE_VARIANT}.img"
fi

# Kata Containers
ROOTFS_BUILD_SCRIPT_DIR="${KATA_CONTAINERS_SRC_DIR}/tools/osbuilder/rootfs-builder"
IMAGE_BUILD_SCRIPT_DIR="${KATA_CONTAINERS_SRC_DIR}/tools/osbuilder/image-builder"

# Kernel built separately by the Makefile's build-kernel target
KERNEL_INSTALL_DIR="${BUILD_DIR}/kernel/usr/share/kata-containers"

mkdir -p "${ROOTFS_DIR}"

# Build the Debian (trixie) guest rootfs via kata-containers' own rootfs-builder
build_debian_rootfs() {
    echo "INFO: Building Debian guest rootfs via kata rootfs-builder (variant: ${IMAGE_VARIANT})"
    local extra_pkgs="ca-certificates"
    # GPU (i915/Xe) firmware for the in-guest DRM driver enabled in the kernel
    # build; the NPU (ivpu) firmware has no Debian package and is installed
    # separately in install_npu_firmware() below.
    [[ "${IMAGE_VARIANT}" != "base" ]] && extra_pkgs="${extra_pkgs} firmware-intel-graphics"
    [[ "${IMAGE_VARIANT}" == "custom" ]] && extra_pkgs="${extra_pkgs} ${CUSTOM_EXTRA_PKGS}"
    pushd "${ROOTFS_BUILD_SCRIPT_DIR}"
    # kata-containers' debian/config.sh still defaults to stretch/10.11 and the
    # Ubuntu mirror; override explicitly rather than depending on an upstream fix.
    if ! ROOTFS_DIR="${ROOTFS_DIR}" OS_VERSION=trixie OS_NAME=trixie \
        REPO_URL=http://deb.debian.org/debian \
        REPO_COMPONENTS="main contrib non-free non-free-firmware" \
        EXTRA_PKGS="${extra_pkgs}" SECCOMP="${SECCOMP:-yes}" \
        bash ${DEBUG:+-x} ./rootfs.sh debian; then
        echo "ERROR: Failed to build Debian guest rootfs"
        exit 1
    fi
    popd
    echo "INFO: Debian guest rootfs built successfully in ${ROOTFS_DIR}"
}

# Copy the kernel produced by the Makefile's build-kernel target next to the image
install_kernel() {
    local vmlinuz
    vmlinuz=$(find "${KERNEL_INSTALL_DIR}" -maxdepth 1 -type f -name "vmlinuz-*" ! -name "*.container")
    if [ "$(echo "${vmlinuz}" | wc -l)" -ne 1 ]; then
        echo "ERROR: Expected exactly one kernel image in ${KERNEL_INSTALL_DIR}, found: ${vmlinuz}"
        exit 1
    fi
    cp "${vmlinuz}" "${BUILD_DIR}"
    chmod 644 "${BUILD_DIR}/$(basename "${vmlinuz}")"
    echo "INFO: Kernel copied successfully to ${BUILD_DIR}"
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

# Download jq binary with SHA256 verification
download_jq() {
    echo "INFO: Downloading jq binary"
    local jq_version="1.7.1"
    local jq_sha256="5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5"
    local bin_src="${GPU_TELEMETRY_DIR}/binaries"
    local jq_path="${bin_src}/jq"
    
    mkdir -p "${bin_src}"
    curl -fsSL --retry 3 "https://github.com/jqlang/jq/releases/download/jq-${jq_version}/jq-linux-amd64" -o "${jq_path}"
    
    # Verify SHA256 checksum
    echo "${jq_sha256}  ${jq_path}" | sha256sum -c - > /dev/null || {
        echo "ERROR: jq binary checksum verification failed"
        exit 1
    }
    chmod +x "${jq_path}"
    echo "INFO: jq downloaded and verified successfully"
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

# Install NPU telemetry binary and config into the rootfs.
install_npu_telemetry() {
    echo "INFO: Installing NPU telemetry agent in rootfs"
    local bin_src="${NPU_TELEMETRY_DIR}/binaries"
    local files_src="${NPU_TELEMETRY_DIR}/files"

    [[ -d "${bin_src}" ]]             || { echo "ERROR: ${bin_src} not found"; exit 1; }
    [[ -x "${bin_src}/npu-reader" ]]  || { echo "ERROR: npu-reader not found in ${bin_src}"; exit 1; }
    [[ -d "${files_src}" ]]           || { echo "ERROR: ${files_src} not found"; exit 1; }

    mkdir -p "${ROOTFS_DIR}/etc/npu-telemetry" \
             "${ROOTFS_DIR}/etc/udev/rules.d" \
             "${ROOTFS_DIR}/usr/local/bin" \
             "${ROOTFS_DIR}/usr/lib/systemd/system/kata-containers.target.wants"
    install -o root -g root -m 0550 "${bin_src}/npu-reader"                           "${ROOTFS_DIR}/usr/local/bin/npu-reader"
    install -o root -g root -m 0550 "${files_src}/npu-telemetry-agent.sh"             "${ROOTFS_DIR}/usr/local/bin/npu-telemetry-agent.sh"
    install -o root -g root -m 0440 "${files_src}/npu-telemetry-guest.env"            "${ROOTFS_DIR}/etc/npu-telemetry/npu-telemetry.env"
    install -o root -g root -m 0440 "${files_src}/npu-telemetry-guest.service"        "${ROOTFS_DIR}/usr/lib/systemd/system/npu-telemetry.service"
    ln -sf ../npu-telemetry.service  "${ROOTFS_DIR}/usr/lib/systemd/system/kata-containers.target.wants/npu-telemetry.service"
    install -o root -g root -m 0444 "${files_src}/90-npu-telemetry.rules"             "${ROOTFS_DIR}/etc/udev/rules.d/90-npu-telemetry.rules"

    echo "INFO: NPU telemetry installed successfully"
    echo "INFO: Cleaning up NPU telemetry binaries"
    rm -rf "${bin_src}"
}

# Install Intel NPU (ivpu) firmware into the rootfs. Debian has no package
# for this, so fetch the exact blobs the in-kernel ivpu driver requests
# (see drivers/accel/ivpu/ivpu_fw.c) directly from upstream linux-firmware.git
# via git.kernel.org's lightweight cgit "plain" endpoint (a few MB per file,
# vs. ~800MB for a full git clone of that repo) pinned to a fixed commit and
# verified by checksum, rather than depending on a vendor GitHub release CDN.
install_npu_firmware() {
    echo "INFO: Installing Intel NPU firmware in rootfs"
    local commit="15980c983529328f5d81139c0b1f7fb505cd96e9"
    local base_url="https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/plain/intel/vpu"
    local fw_dest="${ROOTFS_DIR}/lib/firmware/intel/vpu"
    local tmp_dir
    tmp_dir=$(mktemp -d)

    # name -> sha256
    local -A fw_files=(
        [vpu_37xx_v1.bin]="4078ca4af807e3f28b095df0c7539482ec79afc8c69160ef0480e6d7b67722e6"
        [vpu_40xx_v1.bin]="cdfe2ebd66aaec21d896134c93d82d60de2d8eede75a2c62898aeb9006e5a26f"
        [vpu_50xx_v1.bin]="c8ca936bc259198f040b1623ff632fd44b66ec006067c646dceb24b2ee3fbb3e"
    )

    for name in "${!fw_files[@]}"; do
        curl -fsSL --retry 3 "${base_url}/${name}?id=${commit}" -o "${tmp_dir}/${name}"
        echo "${fw_files[${name}]}  ${tmp_dir}/${name}" | sha256sum -c - > /dev/null || {
            echo "ERROR: NPU firmware checksum verification failed for ${name}"
            exit 1
        }
    done

    mkdir -p "${fw_dest}"
    install -o root -g root -m 0444 "${tmp_dir}"/*.bin "${fw_dest}/"
    rm -rf "${tmp_dir}"
    echo "INFO: Intel NPU firmware installed successfully"
}

#build Trusted vm image from rootfs
build_trusted_vm_image() {
    echo "INFO: Starting Trusted VM image build"
    pushd "${IMAGE_BUILD_SCRIPT_DIR}"
    # erofs keeps the guest image compressed and read-only for minimal size
    if ! IMAGE="${TRUSTED_VM_IMAGE}" FS_TYPE=erofs bash ${DEBUG:+-x} ./image_builder.sh "${ROOTFS_DIR}"; then
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
build_debian_rootfs
install_kernel
if [[ "${IMAGE_VARIANT}" != "base" ]]; then
    install_guest_hooks
    download_jq
    install_gpu_telemetry
    install_npu_telemetry
    install_npu_firmware
fi
build_trusted_vm_image
copy_tc_image
