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

if [ -z "$VERSION" ]; then
	echo "ERROR: Version argument is empty"
	exit 1
fi
KATA_DEPLOY_IMAGE_VERSION="$VERSION"


KATA_ARTIFACT_RELEASE_URL="https://github.com/kata-containers/kata-containers/releases/download/${KATA_CONTAINERS_TAG}/kata-static-${KATA_CONTAINERS_TAG}-amd64.tar.zst"
KATA_ARTIFACT_FILE_NAME=$(basename "${KATA_ARTIFACT_RELEASE_URL##*/}")
KATA_ARTIFACT_DIR="${KATA_ARTIFACT_FILE_NAME%.tar.zst}"
KATA_ARTIFACT_NEW_NAME="kata-static.tar.zst"
KATA_BOOT_COMPONENT_DIR="${KATA_ARTIFACT_DIR}/opt/kata/share/kata-containers"
KATA_CONFIG_DIR="${KATA_ARTIFACT_DIR}/opt/kata/share/defaults/kata-containers"
KATA_DOCKERFILE="${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/Dockerfile"
KATA_ARTIFACT_KERNEL_NAME="vmlinux.container"
KATA_ARTIFACT_ROOTFS_NAME="kata-containers.img"

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
	# List files in current directory after build for debug
	echo "INFO: Listing files in build folder after edge microvisor build:"
	ls -alh build
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

#check if the boot component directory exists
check_dir_exists "${KATA_BOOT_COMPONENT_DIR}"

#create bm-agents group if it does not exist
getent group bm-agents > /dev/null || groupadd -g 500 bm-agents

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
ln -sf "${EDGE_MICROVISOR_ROOTFS}" "${KATA_BOOT_COMPONENT_DIR}/${KATA_ARTIFACT_ROOTFS_NAME}"

# Enable virtio_mem in configuration.toml to fix kernel 6.12 memory hotplug issue
# NOTE: This workaround is required for kernel 6.12.x due to broken memory probe mechanism
echo "INFO: Enabling virtio_mem in configuration.toml for kernel 6.12 compatibility"
KATA_CONFIG_FILE="${KATA_CONFIG_DIR}/configuration.toml"
if [ -f "${KATA_CONFIG_FILE}" ]; then
    sed -i 's/^enable_virtio_mem = false/enable_virtio_mem = true/' "${KATA_CONFIG_FILE}"
    if grep -q '^enable_virtio_mem = true$' "${KATA_CONFIG_FILE}"; then
        echo "INFO: virtio_mem enabled in ${KATA_CONFIG_FILE}"
    else
        echo "ERROR: failed to enable virtio_mem in ${KATA_CONFIG_FILE}"
        exit 1
    fi

    # Enable guest hooks for GPU device readiness wait
    echo "INFO: Enabling guest_hook_path in configuration.toml"
    sed -i 's|^guest_hook_path = ""$|guest_hook_path = "/usr/share/oci/hooks"|' "${KATA_CONFIG_FILE}"
    if grep -q '^guest_hook_path = "/usr/share/oci/hooks"' "${KATA_CONFIG_FILE}"; then
        echo "INFO: guest_hook_path enabled in ${KATA_CONFIG_FILE}"
    else
        echo "ERROR: failed to enable guest_hook_path in ${KATA_CONFIG_FILE}"
        exit 1
    fi

    # Add memhp_default_state=online to kernel parameters for memory hotplug
    echo "INFO: Adding memhp_default_state=online to kernel parameters"
    if grep -q '^kernel_params = ' "${KATA_CONFIG_FILE}"; then
        sed -i 's/^\(kernel_params = ".*\)"/\1 memhp_default_state=online"/' "${KATA_CONFIG_FILE}"
        if grep -q '^kernel_params = ".*memhp_default_state=online' "${KATA_CONFIG_FILE}"; then
            echo "INFO: memhp_default_state=online added to kernel parameters"
        else
            echo "ERROR: failed to add memhp_default_state=online to kernel parameters"
            exit 1
        fi
    else
        echo "WARNING: kernel_params line not found in ${KATA_CONFIG_FILE}"
    fi

    # Enable additional annotations in configuration.toml
    echo "INFO: Enabling additional annotations in configuration.toml"
    extra_annotations=("pcie_root_port" "hot_plug_vfio" "enable_virtio_mem" "default_memory")
    annotations_str=""
    for ann in "${extra_annotations[@]}"; do
        annotations_str+=", \"${ann}\""
    done
    sed -i "s/^\(enable_annotations = \[.*\)\]/\1${annotations_str}]/" "${KATA_CONFIG_FILE}"
else
    echo "ERROR: configuration.toml not found at ${KATA_CONFIG_FILE}"
    exit 1
fi

#build kata binary and copy to artifacts
"${BUILD_DIR}/build-kata-binary.sh"
cp "${BUILD_DIR}/kata-runtime" "${KATA_ARTIFACT_DIR}/opt/kata/bin/"
cp "${BUILD_DIR}/containerd-shim-kata-v2" "${KATA_ARTIFACT_DIR}/opt/kata/bin/"
rm -rf "${BUILD_DIR}/kata-runtime" "${BUILD_DIR}/containerd-shim-kata-v2"

# Iterate over all files, directories, clean up unwanted files and directories and set permission and onwership
chmod 750 "${KATA_ARTIFACT_DIR}/opt/kata"
chown root:bm-agents "${KATA_ARTIFACT_DIR}/opt/kata"

pushd "${KATA_ARTIFACT_DIR}/opt/kata"
for file in $(find . -type f -o -type d -o -type l | sed 's|^\./||'); do
	match=$(awk -v search="$file" '$0 ~ search { print $0; found=1; exit } END { if (!found) print ""; exit }' ../../../kata_keeplist.txt)
    if [[ -n "$match" ]]; then
		chown $(echo "$match" | awk '{print $2}') "$file"
		chmod $(echo "$match" | awk '{print $3}') "$file"
	else
		if [[ "$file" == *"$EDGE_MICROVISOR_KERNEL"* ]]; then
			chown root:bm-agents "$file" && chmod 640 "$file"
		elif [[ "$file" == *"$EDGE_MICROVISOR_KERNEL_CONFIG"* ]]; then
			chown root:root "$file" && chmod 600 "$file"
		else
			rm -rf "$file"
		fi
	fi
done
popd

#build tc-docker-deploy wrapper and copy to artifacts
echo "INFO: Building tc-docker-deploy binary using rust:1.90 container"
docker run --rm \
	-v "${BUILD_DIR}/tc-docker-deploy:/workspace" \
	-w /workspace \
	rust:1.90 \
	bash -c "rustup target add x86_64-unknown-linux-musl && \
		cargo build --locked --release --target x86_64-unknown-linux-musl"

cp "${BUILD_DIR}/tc-docker-deploy/target/x86_64-unknown-linux-musl/release/tc-docker-deploy" "${KATA_ARTIFACT_DIR}/opt/kata/bin/"
chmod 755 "${KATA_ARTIFACT_DIR}/opt/kata/bin/tc-docker-deploy"
chown root:root "${KATA_ARTIFACT_DIR}/opt/kata/bin/tc-docker-deploy"
echo "INFO: tc-docker-deploy binary installed to ${KATA_ARTIFACT_DIR}/opt/kata/bin/tc-docker-deploy"

#retar the artifacts
echo "INFO: Retar the artifacts"
tar --zstd -cf "${KATA_ARTIFACT_NEW_NAME}" -C "${KATA_ARTIFACT_DIR}" .

#remove kata repo if it exists
[ -d "${KATA_CONTAINERS_DIR}" ] && rm -rf "${KATA_CONTAINERS_DIR}"

#clone the kata containers repo
echo "INFO: Cloning Kata Containers repo"
git clone --branch "${KATA_CONTAINERS_TAG}" "${KATA_CONTAINERS_SRC}"

#patch the kata-deploy Dockerfile to add tc-docker-deploy support
"${BUILD_DIR}/patch-dockerfile.sh" "${KATA_DOCKERFILE}"

mkdir -p "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/kata-artifacts"

#copy the build artifacts to the kata repo with version suffix
echo "INFO: Copying build artifacts to Kata Containers repo"
cp "${KATA_ARTIFACT_NEW_NAME}" "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/kata-artifacts/kata-static-${KATA_CONTAINERS_TAG}-amd64.tar.zst"

#build kata-deploy-static component tarballs required by new Dockerfile
echo "INFO: Building kata-deploy-static component tarballs"
pushd "${KATA_CONTAINERS_DIR}"
bash tools/packaging/kata-deploy/local-build/kata-deploy-build-components-tarballs.sh all
cp tools/packaging/kata-deploy/local-build/build/kata-deploy-static-*.tar.zst tools/packaging/kata-deploy/kata-artifacts/
popd

#package tc-docker-deploy as a separate kata-deploy-static tarball (-> /usr/bin/tc-docker-deploy in image)
echo "INFO: Packaging tc-docker-deploy as kata-deploy-static tarball"
_TC_PKG_DIR=$(mktemp -d)
mkdir -p "${_TC_PKG_DIR}/usr/bin"
cp "${BUILD_DIR}/tc-docker-deploy/target/x86_64-unknown-linux-musl/release/tc-docker-deploy" "${_TC_PKG_DIR}/usr/bin/"
tar --zstd -cf "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/kata-artifacts/kata-deploy-static-tc-docker-deploy.tar.zst" -C "${_TC_PKG_DIR}" .
rm -rf "${_TC_PKG_DIR}"

#patch shim-components.json so kata-deploy finds our monolithic kata-static tarball at runtime
"${BUILD_DIR}/patch-shim-components.sh" "${KATA_CONTAINERS_DIR}/tools/packaging/kata-deploy/shim-components.json" "${KATA_CONTAINERS_TAG}"

#build the kata deploy image
pushd "${KATA_CONTAINERS_DIR}"
echo "INFO: Building Kata deploy image"
docker build -f tools/packaging/kata-deploy/Dockerfile -t "${KATA_DEPLOY_IMAGE_NAME}":"${KATA_DEPLOY_IMAGE_VERSION}" .
popd

#cleanup
rm -rf "${KATA_ARTIFACT_DIR}"
rm -rf "${KATA_CONTAINERS_DIR}"
rm -f "${KATA_ARTIFACT_FILE_NAME}"
rm -f "${KATA_ARTIFACT_NEW_NAME}"
