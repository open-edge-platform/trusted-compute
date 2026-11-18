#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

# Variables
BUILD_DIR := $(shell pwd)/build
export GOTOOLCHAIN := go1.27.4
MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
$(if $(shell command -v yq 2>/dev/null),,$(error ERROR: yq command not found. Please install yq))

EDGE_MICROVISOR_SRC=https://github.com/open-edge-platform/edge-microvisor-toolkit.git
EDGE_MICROVISOR_BRANCH?=26.06
EDGE_MICROVISOR_COMMIT?="26.06-20260722"
EDGE_MICROVISOR_SRC_DIR=$(BUILD_DIR)/microvisor_src
EDGE_MICROVISOR_IMAGE_CONFIG=$(EDGE_MICROVISOR_SRC_DIR)/toolkit/imageconfigs/trusted-compute-os.json
# Must match TCVM_EMT_BUILT_CONFIG in os/emt/emt_profile.sh
EDGE_MICROVISOR_BUILT_CONFIG=$(EDGE_MICROVISOR_SRC_DIR)/out/images/trusted-compute-os/trusted-compute-os.json

# Image features: TCVM_CONFIG holds the saved selection
TCVM_CONFIG?=$(MAKEFILE_DIR).tcvm.config
TCVM_RESOLVED_CONFIG=$(BUILD_DIR)/tcvm.config
TCVM_CONFIG_TOOL=bash $(MAKEFILE_DIR)tcvm_config.sh --config $(TCVM_CONFIG)

KATA_CONTAINERS_SRC=https://github.com/kata-containers/kata-containers.git
KATA_CONTAINERS_TAG?=$(shell yq '.kata-containers.version' $(MAKEFILE_DIR)../trusted-workload/kata-deploy/version.yaml)
KATA_CONTAINERS_SRC_DIR=$(BUILD_DIR)/kata_src
 
# Targets
.PHONY: all clone clone-microvisor clone-kata build build-microvisor-image build-tcvm-image build-tcvm-agent clean-all clean clean-microvisor clean-kata help lint test \
	menuconfig defconfig resolve-config check-base-image
 
all:
	@# Help: Runs build all
	sudo true  # Prompt for password once
	sudo -E $(MAKE) clone build-microvisor-image build-tcvm-image

menuconfig:
	@# Help: Select Trusted-VM image features in an interactive menu
	$(TCVM_CONFIG_TOOL) --gui

defconfig:
	@# Help: Create/reset .tcvm.config with defaults (all features except debug) for manual editing
	$(TCVM_CONFIG_TOOL) --defaults

resolve-config:
	sudo mkdir -p $(BUILD_DIR)
	sudo rm -f $(TCVM_RESOLVED_CONFIG)
	sudo -E $(TCVM_CONFIG_TOOL) --env --output $(TCVM_RESOLVED_CONFIG)

# Fails fast if the EMT tarball was built for a different selection than build/tcvm.config
check-base-image: resolve-config
	bash $(MAKEFILE_DIR)tcvm_config.sh --config $(TCVM_RESOLVED_CONFIG) --check-base-image

clone: clone-microvisor clone-kata
	@# Help: Runs clone all

clone-microvisor:
	@# Help: Runs clone microvisor and checks out to a specific commit ID
	mkdir -p $(BUILD_DIR)
	rm -rf "$(EDGE_MICROVISOR_SRC_DIR)"
	git clone -b $(EDGE_MICROVISOR_BRANCH) $(EDGE_MICROVISOR_SRC) $(EDGE_MICROVISOR_SRC_DIR)
	cd $(EDGE_MICROVISOR_SRC_DIR) && git checkout $(EDGE_MICROVISOR_COMMIT)

clone-kata:
	@# Help: Runs clone kata containers
	mkdir -p $(BUILD_DIR)
	rm -rf "$(KATA_CONTAINERS_SRC_DIR)"
	git clone -b $(KATA_CONTAINERS_TAG) $(KATA_CONTAINERS_SRC) $(KATA_CONTAINERS_SRC_DIR)
 
build: clone build-microvisor-image build-tcvm-image clean-microvisor clean-kata clean-rootfs
	@# Help: Runs build all

build-microvisor-image: resolve-config
	@# Help: Runs build image phase only
	sudo true  # Prompt for password once
	@# Generated inside EMT imageconfigs so its relative packagelists/additionalconfigs/scripts paths resolve
	sudo bash $(MAKEFILE_DIR)tcvm_config.sh --config $(TCVM_RESOLVED_CONFIG) --show \
		--gen-image-config $(EDGE_MICROVISOR_IMAGE_CONFIG)
	sudo rm -f $(EDGE_MICROVISOR_BUILT_CONFIG)
	cd $(EDGE_MICROVISOR_SRC_DIR)/toolkit && sudo -E make image CONFIG_FILE=./imageconfigs/trusted-compute-os.json -j$$(nproc) REBUILD_TOOLS=y REBUILD_PACKAGES=n
	sudo cp $(EDGE_MICROVISOR_IMAGE_CONFIG) $(EDGE_MICROVISOR_BUILT_CONFIG)

build-tcvm-image: resolve-config check-base-image build-tcvm-agent
	@# Help: Runs build Trusted VM image
	sudo true  # Prompt for password once
	sudo TCVM_CONFIG_FILE=$(TCVM_RESOLVED_CONFIG) bash $(MAKEFILE_DIR)/tcvm_image_build.sh

build-tcvm-agent:
	@# Help: Runs build trusted VM agent
	sudo true  # Prompt for password once
	cd tcvm-agent && bash ./tcvm_agent_build.sh

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

clean: clean-microvisor clean-kata clean-rootfs
	@# Help: Runs clean all
	sudo rm -rf $(BUILD_DIR)

clean-microvisor:
	@# Help: Runs clean microvisor
	sudo rm -rf $(EDGE_MICROVISOR_SRC_DIR)

clean-kata:
	@# Help: Runs clean kata containers
	sudo rm -rf $(KATA_CONTAINERS_SRC_DIR)

clean-rootfs:
	@# Help: Runs clean rootfs
	sudo rm -rf $(BUILD_DIR)/rootfs

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
