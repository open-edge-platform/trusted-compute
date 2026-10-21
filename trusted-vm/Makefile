#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

# Variables
BUILD_DIR := $(shell pwd)/build
export GOTOOLCHAIN := go1.26.0
MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
$(if $(shell command -v yq 2>/dev/null),,$(error ERROR: yq command not found. Please install yq))

OS_DIR := $(MAKEFILE_DIR)os
GUEST_OS?=emt
SUPPORTED_GUEST_OS := $(notdir $(wildcard $(OS_DIR)/*))
ifeq ($(filter $(GUEST_OS),$(SUPPORTED_GUEST_OS)),)
$(error ERROR: GUEST_OS must be one of: $(SUPPORTED_GUEST_OS) (got '$(GUEST_OS)'))
endif
GUEST_OS_BUILD_SCRIPT := $(OS_DIR)/$(GUEST_OS)/build_$(GUEST_OS).sh

# Feature set of the image; each variant adds to the one before it.
IMAGE_VARIANT?=npu
ifeq ($(filter $(IMAGE_VARIANT),minimal gpu npu custom),)
$(error ERROR: IMAGE_VARIANT must be one of: minimal, gpu, npu, custom (got '$(IMAGE_VARIANT)'))
endif
CUSTOM_EXTRA_PKGS?=strace gdb pciutils procps iproute2

EDGE_MICROVISOR_SRC=https://github.com/open-edge-platform/edge-microvisor-toolkit.git
EDGE_MICROVISOR_BRANCH?=26.06
EDGE_MICROVISOR_COMMIT?="26.06-20260722"
EDGE_MICROVISOR_SRC_DIR=$(BUILD_DIR)/microvisor_src
# One shared EMT config; per-variant packages are appended to its PackageLists at build time.
EMT_IMAGECONFIG_DIR=$(OS_DIR)/emt/imageconfigs
EMT_BASE_IMAGECONFIG=$(EMT_IMAGECONFIG_DIR)/emt-os.json
EMT_IMAGECONFIG=emt-os-$(IMAGE_VARIANT).json
EMT_PKGLISTS_minimal:=
EMT_PKGLISTS_gpu:=gpu
EMT_PKGLISTS_npu:=npu
EMT_PKGLISTS_custom:=custom
EMT_TOOLKIT_IMAGECONFIG_DIR=$(EDGE_MICROVISOR_SRC_DIR)/toolkit/imageconfigs

KATA_CONTAINERS_SRC=https://github.com/kata-containers/kata-containers.git
KATA_CONTAINERS_TAG?=$(shell yq '.kata-containers.version' $(MAKEFILE_DIR)../trusted-workload/kata-deploy/version.yaml)
KATA_CONTAINERS_SRC_DIR=$(BUILD_DIR)/kata_src
# Only used for GUEST_OS=debian; EMT ships its own prebuilt kernel in /boot.
# Defaults to the version kata-containers pins.
KERNEL_VERSION?=
KERNEL_INSTALL_DIR=$(BUILD_DIR)/kernel
KERNEL_CONFIG_FRAGMENTS:=$(wildcard $(OS_DIR)/debian/kernel-config/*.conf)


# Targets
.PHONY: all clone clone-kata clone-microvisor build build-kernel build-microvisor-image build-tvm-agent build-tvm-image image clean-all clean clean-kata clean-kernel clean-microvisor clean-rootfs help lint test

all:
	@# Help: Runs build all
	sudo true  # Prompt for password once
	sudo -E $(MAKE) clone build-tvm-image

clone: clone-kata
	@# Help: Runs clone all
ifeq ($(GUEST_OS),emt)
	$(MAKE) clone-microvisor
endif

clone-kata:
	@# Help: Runs clone kata containers
	mkdir -p $(BUILD_DIR)
	rm -rf "$(KATA_CONTAINERS_SRC_DIR)"
	git clone -b $(KATA_CONTAINERS_TAG) $(KATA_CONTAINERS_SRC) $(KATA_CONTAINERS_SRC_DIR)

clone-microvisor:
	@# Help: Runs clone microvisor and checks out to a specific commit ID (GUEST_OS=emt only)
	mkdir -p $(BUILD_DIR)
	rm -rf "$(EDGE_MICROVISOR_SRC_DIR)"
	git clone -b $(EDGE_MICROVISOR_BRANCH) $(EDGE_MICROVISOR_SRC) $(EDGE_MICROVISOR_SRC_DIR)
	cd $(EDGE_MICROVISOR_SRC_DIR) && git checkout $(EDGE_MICROVISOR_COMMIT)

build: clone build-tvm-image clean-kata clean-rootfs
	@# Help: Runs build all

build-kernel: clone-kata
	@# Help: Builds the guest kernel from kata-containers source (GUEST_OS=debian only; with Intel GPU/NPU passthrough driver support per IMAGE_VARIANT)
	sudo true  # Prompt for password once
	version="$(KERNEL_VERSION)"; \
	[ -n "$$version" ] || version=$$(yq '.assets.kernel.version' $(KATA_CONTAINERS_SRC_DIR)/versions.yaml); \
	cd $(KATA_CONTAINERS_SRC_DIR)/tools/packaging/kernel && \
	sudo -E ./build-kernel.sh -v "$$version" -f setup && \
	version_no_v="$${version#v}"; \
	kernel_src_dir=$$(find . -maxdepth 1 -type d -name "kata-linux-$${version_no_v}-*" | head -n1); \
	[ -n "$$kernel_src_dir" ] || { echo "ERROR: failed to locate kernel source dir for version $$version" >&2; exit 1; }; \
	if [ -n "$(KERNEL_CONFIG_FRAGMENTS)" ]; then \
		sudo -E bash -c "cd '$$kernel_src_dir' && scripts/kconfig/merge_config.sh -m .config $(KERNEL_CONFIG_FRAGMENTS) && make ARCH=x86_64 olddefconfig"; \
	fi && \
	sudo -E ./build-kernel.sh -v "$$version" build && \
	sudo -E DESTDIR=$(KERNEL_INSTALL_DIR) PREFIX=/usr ./build-kernel.sh -v "$$version" install

build-microvisor-image:
	@# Help: Builds the Edge Microvisor Toolkit rootfs image for IMAGE_VARIANT (GUEST_OS=emt only)
	sudo true  # Prompt for password once
	# Our package lists sit next to the toolkit's own, so PackageLists entries resolve relative to imageconfigs/.
	sudo install -m 0644 -t "$(EMT_TOOLKIT_IMAGECONFIG_DIR)/packagelists" $(EMT_IMAGECONFIG_DIR)/packagelists/*.json
	sudo cp "$(EMT_BASE_IMAGECONFIG)" "$(EMT_TOOLKIT_IMAGECONFIG_DIR)/$(EMT_IMAGECONFIG)"
	for list in $(EMT_PKGLISTS_$(IMAGE_VARIANT)); do \
		sudo yq -i -p=json -o=json ".SystemConfigs[0].PackageLists += [\"packagelists/emt-$$list-packages.json\"]" "$(EMT_TOOLKIT_IMAGECONFIG_DIR)/$(EMT_IMAGECONFIG)" || exit 1; \
	done
	cd $(EDGE_MICROVISOR_SRC_DIR)/toolkit && sudo -E make image CONFIG_FILE=./imageconfigs/$(EMT_IMAGECONFIG) -j$$(nproc) REBUILD_TOOLS=y REBUILD_PACKAGES=n

build-tvm-agent:
	@# Help: Builds the Kata agent (musl, cross-built) used by the EMT rootfs (GUEST_OS=emt only)
	sudo true  # Prompt for password once
	cd $(MAKEFILE_DIR)/tvm-agent && bash ./tvm_agent_build.sh

ifeq ($(GUEST_OS),debian)
build-tvm-image: build-kernel
else ifeq ($(GUEST_OS),emt)
build-tvm-image: build-microvisor-image build-tvm-agent
endif
build-tvm-image:
	@# Help: Runs build Trusted VM image (set GUEST_OS=emt|debian|custom, IMAGE_VARIANT=minimal|gpu|npu|custom)
	sudo true  # Prompt for password once
	sudo GUEST_OS="$(GUEST_OS)" IMAGE_VARIANT="$(IMAGE_VARIANT)" CUSTOM_EXTRA_PKGS="$(CUSTOM_EXTRA_PKGS)" bash $(GUEST_OS_BUILD_SCRIPT)

image: build-tvm-image
	@# Help: Builds the Trusted VM image, e.g. make image IMAGE_VARIANT=gpu GUEST_OS=debian

docker-build:
	@echo "This is a dummy docker-build target."

docker-push:
	@echo "This is a dummy docker-push target."

helm-build:
	@echo "This is a dummy helm-build target."

helm-push:
	@echo "This is a dummy helm-push target."

clean-all:
	@# Help: Runs clean-all stage in all subprojects
	@echo "---MAKEFILE CLEAN-ALL---"
	echo $@
	@echo "---END MAKEFILE CLEAN-ALL---"

clean: clean-kata clean-rootfs clean-kernel clean-microvisor
	@# Help: Runs clean all
	sudo rm -rf $(BUILD_DIR)

clean-kata:
	@# Help: Runs clean kata containers
	sudo rm -rf $(KATA_CONTAINERS_SRC_DIR)

clean-microvisor:
	@# Help: Runs clean microvisor
	sudo rm -rf $(EDGE_MICROVISOR_SRC_DIR)

clean-rootfs:
	@# Help: Runs clean rootfs
	sudo rm -rf $(BUILD_DIR)/rootfs

clean-kernel:
	@# Help: Runs clean kernel build output
	sudo rm -rf $(KERNEL_INSTALL_DIR)

lint:
	@# Help: Runs lint stage
	@echo "---MAKEFILE LINT---"
	echo $@
	@echo "---END MAKEFILE LINT---"

test:
	@# Help: Runs test stage
	@echo "---MAKEFILE TEST---"
	echo $@
	@echo "---END MAKEFILE TEST---"

help:
	@printf "%-30s %s\n" "Target" "Description"
	@printf "%-30s %s\n" "------" "-----------"
	@grep -E '^[a-zA-Z0-9_%-]+:|^[[:space:]]+@# Help:' Makefile | \
	awk '\
		/^[a-zA-Z0-9_%-]+:/ { \
			target = $$1; \
			sub(":", "", target); \
		} \
		/^[[:space:]]+@# Help:/ { \
			if (target != "") { \
				help_line = $$0; \
				sub("^[[:space:]]+@# Help: ", "", help_line); \
				printf "%-30s %s\n", target, help_line; \
				target = ""; \
			} \
		}'
