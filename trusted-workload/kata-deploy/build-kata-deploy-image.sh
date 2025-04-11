#!/bin/bash
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

BUILD_DIR="${PWD}"
EDGE_MICROVISOR_SRC="${1:-$(realpath "${BUILD_DIR}/../../trusted-vm/build")}"

#check if yq is installed
if ! command -v yq &> /dev/null; then
	echo "ERROR: yq command not found. Please install yq"
	exit 1
fi

EDGE_MICROVISOR_KERNEL=$(yq '.kernel.name' version.yaml)
EDGE_MICROVISOR_KERNEL_CONFIG=$(yq '.kernel.config' version.yaml)
EDGE_MICROVISOR_ROOTFS=$(yq '.rootfs.name' version.yaml)

KATA_CONTAINERS_SRC=$(yq '.kata-containers.url' version.yaml)
KATA_CONTAINERS_DIR=$(yq '.kata-containers.name' version.yaml)
KATA_CONTAINERS_TAG=$(yq '.kata-containers.version' version.yaml)

KATA_DEPLOY_IMAGE_NAME=$(yq '.kata-deploy.name' version.yaml)
KATA_DEPLOY_IMAGE_VERSION=$(tr -d '[:space:]' < VERSION)

KATA_ARTIFACT_RELEASE_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_CONTAINERS_TAG}/kata-static-${KATA_CONTAINERS_TAG}-amd64.tar.xz"
KATA_ARTIFACT_FILE_NAME=$(basename "${KATA_ARTIFACT_RELEASE_URL##*/}")
KATA_ARTIFACT_DIR="${KATA_ARTIFACT_FILE_NAME%.tar.xz}"
KATA_ARTIFACT_NEW_NAME="kata-static.tar.xz"
KATA_PATCH_DIR="patch/${KATA_CONTAINERS_TAG}"
KATA_BOOT_COMPONENT_DIR="${KATA_ARTIFACT_DIR}/opt/kata/share/kata-containers"
KATA_ARTIFACT_KERNEL_NAME="vmlinux.container"
KATA_ARTIFACT_TOOTFS_NAME="kata-containers.img"


KATA_KEEPLIST_FILE_LIST=( "VERSION" "containerd-shim-kata-v2" "kata-agent-ctl" "kata-collect-data.sh" "kata-ctl" "kata-manager" 
	"kata-manager.sh" "kata-monitor" "kata-runtime" "kata-trace-forwarder" "qemu-system-x86_64" "stratovirt" "fdt.h" "libfdt.h" 
	"libfdt_env.h" "libfdt.a" "libfdt.pc" "virtiofsd" "oci_config.json" "configuration.toml" "configuration-qemu.toml" 
	"genpolicy-settings.json" "rules.rego" "root_hash.txt" "bios-256k.bin" "efi-virtio.rom" "kvmvapic.bin" "linuxboot_dma.bin" 
	"pvh.bin" "versions.yaml" )

KATA_DELETE_FILE_LIST=("runtime-rs" "share/defaults/kata-containers/runtime-rs" "share/kata-qemu/qemu/firmware" "share/kata-qemu-snp-experimental" 
	"lib/kata-qemu-snp-experimental" "share/ovmf" )

check_file_exists() {
    local file="${1}"
    [ -f "$file" ] || { echo "ERROR: File $file not found"; exit 1; }
}

check_dir_exists() {
    local dir="${1}"
    [ -d "$dir" ] || { echo "ERROR: Directory $dir not found"; exit 1; }
}

#check if edge microvisor source directory exists
if [ ! -d "${EDGE_MICROVISOR_SRC}" ]; then
	echo "WARR: Edge microvisor source directory not found"
	echo "INFO: Starting edge microvisor kernel and rootfs build"
	pushd $(realpath "${BUILD_DIR}/../../trusted-vm")
	make build
	popd 
fi

#check if edge microvisor kernel and config file exists
check_file_exists "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_KERNEL}"
check_file_exists "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_KERNEL_CONFIG}"
check_file_exists "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_ROOTFS}"

#check if old artifacts are present and remove them
[ -d "${KATA_ARTIFACT_DIR}" ] && rm -rf "${KATA_ARTIFACT_DIR}"
[ -d "${KATA_ARTIFACT_FILE_NAME}" ] && rm -f "${KATA_ARTIFACT_FILE_NAME}"

#Download the Kata artifacts using curl
echo "INFO: Downloading Kata artifacts"
curl -L -o "${KATA_ARTIFACT_FILE_NAME}" "${KATA_ARTIFACT_RELEASE_URL}"

#Extract the Kata artifacts
echo "INFO: Extracting Kata artifacts"
mkdir -p "${KATA_ARTIFACT_DIR}"
tar -xf "${KATA_ARTIFACT_FILE_NAME}" -C "${KATA_ARTIFACT_DIR}"

# Iterate over files and symlinks in the directory and remove the files not in the keeplist
find "${KATA_ARTIFACT_DIR}" -type f -o -type l | while read -r item; do
  	base_item=$(basename "$item")
  	if [[ ! " ${KATA_KEEPLIST_FILE_LIST[@]} " =~ " ${base_item} " ]]; then
		#echo "INFO: Deleting: $item (not in keeplist)"
		rm -rf "$item"
  	fi
done

#iterate over the delete file list and remove the files
pushd "${KATA_ARTIFACT_DIR}/opt/kata"
for file in "${KATA_DELETE_FILE_LIST[@]}"; do
	echo "INFO: Removing ${file}"
	rm -rf "${file}"
done
popd

#check if the boot component directory exists
check_dir_exists "${KATA_BOOT_COMPONENT_DIR}"

#copy edge microvisor kernel to the kata artifacts
echo "INFO: Copying edge microvisor kernel to the Kata artifacts"
cp "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_KERNEL}" "${KATA_BOOT_COMPONENT_DIR}"

#copy edge microvisor kernel config to the kata artifacts
echo "INFO: Copying edge microvisor kernel config to the Kata artifacts"
cp "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_KERNEL_CONFIG}" "${KATA_BOOT_COMPONENT_DIR}"

#copy edge microvisor rootfs image to the kata artifacts
echo "INFO: Copying edge microvisor rootfs image to the Kata artifacts"
cp "${EDGE_MICROVISOR_SRC}/${EDGE_MICROVISOR_ROOTFS}" "${KATA_BOOT_COMPONENT_DIR}"

#change symlink to point to the new kernel and rootfs
echo "INFO: Change symlink to point to the new kernel and rootfs"
ln -sf "${EDGE_MICROVISOR_KERNEL}" "${KATA_BOOT_COMPONENT_DIR}/${KATA_ARTIFACT_KERNEL_NAME}"
ln -sf "${EDGE_MICROVISOR_ROOTFS}" "${KATA_BOOT_COMPONENT_DIR}/${KATA_ARTIFACT_TOOTFS_NAME}"

#retar the artifacts
echo "INFO: Retar the artifacts"
tar -cJf "${KATA_ARTIFACT_NEW_NAME}" -C "${KATA_ARTIFACT_DIR}" .

#remove kata repo if it exists
[ -d "${KATA_CONTAINERS_DIR}" ] && rm -rf "${KATA_CONTAINERS_DIR}"

#clone the kata containers repo
echo "INFO: Cloning Kata Containers repo"
git clone --branch "${KATA_CONTAINERS_TAG}" "${KATA_CONTAINERS_SRC}"

#apply all the patch to the kata repo from patch directory
if [ -d "$KATA_PATCH_DIR" ]; then
    echo "INFO: Apply patches from ${KATA_PATCH_DIR}"
	patches=($(find "$KATA_PATCH_DIR" -maxdepth 1 -name '*.patch' | sort -t- -k1,1n))
	echo "INFO: Found ${#patches[@]} patches"
	for patch in "${patches[@]}"; do
		echo "INFO: Apply $patch"
		patch -d "${KATA_CONTAINERS_DIR}" -p1 < "$patch" || { echo >&2 "ERROR: Not applied. Exiting..."; exit 1; }
	done
else
    echo "INFO: No patches found in ${KATA_PATCH_DIR}"
fi

#copy the build artifacts to the kata repo
echo "INFO: Copying build artifacts to Kata Containers repo"
cp "${KATA_ARTIFACT_NEW_NAME}" "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/"

#build the kata deploy image
pushd "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy"
echo "INFO: Building Kata deploy image"
docker build -t "${KATA_DEPLOY_IMAGE_NAME}":"${KATA_DEPLOY_IMAGE_VERSION}" .
popd

#cleanup
rm -rf "${KATA_ARTIFACT_DIR}"
rm -rf "${KATA_CONTAINERS_DIR}"
rm -f "${KATA_ARTIFACT_FILE_NAME}"
rm -f "${KATA_ARTIFACT_NEW_NAME}"
