#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

# Variables
BUILD_DIR := $(shell pwd)/build
export GOTOOLCHAIN := go1.26.0
MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
$(if $(shell command -v yq 2>/dev/null),,$(error ERROR: yq command not found. Please install yq))

KATA_CONTAINERS_SRC=https://github.com/kata-containers/kata-containers.git
KATA_CONTAINERS_TAG?=$(shell yq '.kata-containers.version' $(MAKEFILE_DIR)../trusted-workload/kata-deploy/version.yaml)
KATA_CONTAINERS_SRC_DIR=$(BUILD_DIR)/kata_src
# Guest kernel version to build; defaults to the version kata-containers itself pins.
# GPU (i915/Xe) and NPU (ivpu) driver support is enabled via the config
# fragment at kernel-config/gpu-npu.conf, merged into kata's generated
# .config after 'setup' and before 'build' (see build-kernel target below).
KERNEL_VERSION?=
KERNEL_INSTALL_DIR=$(BUILD_DIR)/kernel
GPU_NPU_KERNEL_CONFIG=$(MAKEFILE_DIR)kernel-config/gpu-npu.conf

# Image variant to build:
#   base    - minimal guest rootfs only (default)
#   gpu-npu - base + GPU/NPU telemetry agents and the GPU prestart hook
#   custom  - gpu-npu + extra packages from CUSTOM_EXTRA_PKGS (e.g. debugging tools)
IMAGE_VARIANT?=base
ifeq ($(filter $(IMAGE_VARIANT),base gpu-npu custom),)
$(error ERROR: IMAGE_VARIANT must be one of: base, gpu-npu, custom (got '$(IMAGE_VARIANT)'))
endif
CUSTOM_EXTRA_PKGS?=strace gdb pciutils procps iproute2

# Targets
.PHONY: all clone clone-kata build build-kernel build-tvm-image image-gpu-npu image-custom clean-all clean clean-kata clean-kernel help lint test

all:
	@# Help: Runs build all
	sudo true  # Prompt for password once
	sudo -E $(MAKE) clone build-kernel build-tvm-image

clone: clone-kata
	@# Help: Runs clone all

clone-kata:
	@# Help: Runs clone kata containers
	mkdir -p $(BUILD_DIR)
	rm -rf "$(KATA_CONTAINERS_SRC_DIR)"
	git clone -b $(KATA_CONTAINERS_TAG) $(KATA_CONTAINERS_SRC) $(KATA_CONTAINERS_SRC_DIR)

build: clone build-kernel build-tvm-image clean-kata clean-rootfs
	@# Help: Runs build all

build-kernel: clone-kata
	@# Help: Builds the guest kernel from kata-containers source (with Intel GPU/NPU passthrough driver support)
	sudo true  # Prompt for password once
	version="$(KERNEL_VERSION)"; \
	[ -n "$$version" ] || version=$$(yq '.assets.kernel.version' $(KATA_CONTAINERS_SRC_DIR)/versions.yaml); \
	cd $(KATA_CONTAINERS_SRC_DIR)/tools/packaging/kernel && \
	sudo -E ./build-kernel.sh -v "$$version" -f setup && \
	version_no_v="$${version#v}"; \
	kernel_src_dir=$$(find . -maxdepth 1 -type d -name "kata-linux-$${version_no_v}-*" | head -n1); \
	[ -n "$$kernel_src_dir" ] || { echo "ERROR: failed to locate kernel source dir for version $$version" >&2; exit 1; }; \
	sudo -E bash -c "cd '$$kernel_src_dir' && scripts/kconfig/merge_config.sh -m .config '$(GPU_NPU_KERNEL_CONFIG)' && make ARCH=x86_64 olddefconfig" && \
	sudo -E ./build-kernel.sh -v "$$version" build && \
	sudo -E DESTDIR=$(KERNEL_INSTALL_DIR) PREFIX=/usr ./build-kernel.sh -v "$$version" install

build-tvm-image: build-kernel
	@# Help: Runs build Trusted VM image (set IMAGE_VARIANT=base|gpu-npu|custom, default base)
	sudo true  # Prompt for password once
	sudo IMAGE_VARIANT="$(IMAGE_VARIANT)" CUSTOM_EXTRA_PKGS="$(CUSTOM_EXTRA_PKGS)" bash $(MAKEFILE_DIR)/tvm_image_build.sh

image-gpu-npu:
	@# Help: Builds the GPU/NPU-enabled Trusted VM image
	$(MAKE) build-tvm-image IMAGE_VARIANT=gpu-npu

image-custom:
	@# Help: Builds the custom Trusted VM image (GPU/NPU + CUSTOM_EXTRA_PKGS)
	$(MAKE) build-tvm-image IMAGE_VARIANT=custom

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

clean: clean-kata clean-rootfs clean-kernel
	@# Help: Runs clean all
	sudo rm -rf $(BUILD_DIR)

clean-kata:
	@# Help: Runs clean kata containers
	sudo rm -rf $(KATA_CONTAINERS_SRC_DIR)

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
