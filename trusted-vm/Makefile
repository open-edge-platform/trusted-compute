#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

# Variables
BUILD_DIR := $(shell pwd)/build

EDGE_MICROVISOR_SRC=https://github.com/open-edge-platform/edge-microvisor-toolkit.git
EDGE_MICROVISOR_BRANCH?=3.0
EDGE_MICROVISOR_COMMIT?="96eb3660c58a48ada021e2c0eaa0510cad6dc119"
EDGE_MICROVISOR_SRC_DIR=$(BUILD_DIR)/microvisor_src

KATA_CONTAINERS_SRC=https://github.com/kata-containers/kata-containers.git
KATA_CONTAINERS_TAG?=3.15.0
KATA_CONTAINERS_SRC_DIR=$(BUILD_DIR)/kata_src

MAKEFILE_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))
 
# Targets
.PHONY: all clone clone-microvisor clone-kata build build-microvisor-image build-tvm-image build-tvm-agent clean-all clean clean-microvisor clean-kata help lint test
 
all:
	@# Help: Runs build all
	sudo true  # Prompt for password once
	sudo -E $(MAKE) clone build-microvisor-image build-tvm-image

clone: clone-microvisor clone-kata
	@# Help: Runs clone all

clone-microvisor:
	@# Help: Runs clone microvisor and checks out to a specific commit ID
	mkdir -p $(BUILD_DIR)
	rm -rf "$(EDGE_MICROVISOR_SRC_DIR)"
	git lfs install
	git clone -b $(EDGE_MICROVISOR_BRANCH) $(EDGE_MICROVISOR_SRC) $(EDGE_MICROVISOR_SRC_DIR)
	git lfs pull
	cd $(EDGE_MICROVISOR_SRC_DIR) && git checkout $(EDGE_MICROVISOR_COMMIT)

clone-kata:
	@# Help: Runs clone kata containers
	mkdir -p $(BUILD_DIR)
	rm -rf "$(KATA_CONTAINERS_SRC_DIR)"
	git clone -b $(KATA_CONTAINERS_TAG) $(KATA_CONTAINERS_SRC) $(KATA_CONTAINERS_SRC_DIR)
 
build: clone build-microvisor-image build-tvm-image
	@# Help: Runs build all

build-microvisor-image:
	@# Help: Runs build image phase only
	sudo true  # Prompt for password once
	#cd $(EDGE_MICROVISOR_SRC_DIR)/toolkit && sudo make image CONFIG_FILE=./imageconfigs/trusted-compute-os.json -j$$(nproc) REBUILD_TOOLS=y REBUILD_PACKAGES=y
	mkdir -p $(EDGE_MICROVISOR_SRC_DIR)/out/images/trusted-compute-os
	cp $(MAKEFILE_DIR)Trusted-Compute-3.0.20250408.0913.tar.gz $(EDGE_MICROVISOR_SRC_DIR)/out/images/trusted-compute-os

build-tvm-image: build-tvm-agent
	@# Help: Runs build Trusted VM image
	sudo true  # Prompt for password once
	sudo bash $(MAKEFILE_DIR)/tvm_image_build.sh

build-tvm-agent:
	@# Help: Runs build trusted VM agent
	sudo true  # Prompt for password once
	cd tvm-agent && bash ./tvm_agent_build.sh

docker-build:
	@echo "This is a dummy docker-build target."

docker-push:
	@echo "This is a dummy docker-push target."

clean-all:
	@# Help: Runs clean-all stage in all subprojects
	@echo "---MAKEFILE CLEAN-ALL---"
	echo $@
	@echo "---END MAKEFILE CLEAN-ALL---"

clean: clean-microvisor clean-kata
	@# Help: Runs clean all
	sudo rm -rf $(BUILD_DIR)

clean-microvisor:
	@# Help: Runs clean microvisor
	sudo rm -rf $(EDGE_MICROVISOR_SRC_DIR)

clean-kata:
	@# Help: Runs clean kata containers
	sudo rm -rf $(KATA_CONTAINERS_SRC_DIR)

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

docker-build:
	@echo "---Docker Build---"
	echo $@
	@echo "---End Docker Build---"

docker-push: ## Push docker images.
	@echo "---Docker push images---"
	echo $@
	@echo "---END Docker push images---"

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
