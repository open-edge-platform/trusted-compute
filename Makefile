
#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

SUBPROJECTS := helm attestation-verifier attestation-manager trusted-workload trusted-vm

VENV_NAME	 := venv

# Path variables
OUT_DIR       := out

# If out dir doesn't exist, create it
$(OUT_DIR):
	mkdir -p $(OUT_DIR)/trusted-vm $(OUT_DIR)/attestation-verifier $(OUT_DIR)/attestation-manager $(OUT_DIR)/trusted-workload

all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects
	
build:  helm build-attestation-verifier build-attestation-manager build-trusted-workload 
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
	@echo "---END MAKEFILE Build---"

build-helm:
	@# Help: Runs build stage in helm  subproject
	make -C ${PWD}/helm

build-trusted-vm:
	@# Help: Runs build stage in trusted-vm  subprojects
	make -C ${PWD}/trusted-vm build

build-attestation-verifier:
	@# Help: Runs build stage in attestation-verifier subprojects
	make -C ${PWD}/attestation-verifier docker-build

build-attestation-manager: $(eval SHELL:=/bin/bash)
	@# Help: Runs build stage in attestation-manager subprojects
	#echo " add build step in below line"
	echo " building attestation manager"
	make -C ${PWD}/attestation-manager build docker-build

build-trusted-workload:
	@# Help: Runs build stage in trusted-workload subprojects
	make -C ${PWD}/trusted-workload build

license: requirements.txt
	@# Help: Check licensing with the reuse tool
	set -u ;\
	python -m pip install --upgrade pip ;\
	python -m pip install -r requirements.txt;\
	reuse --version ;\
	reuse --root . lint

lint:
	@# Help: Runs lint stage in all subprojects
	@echo "---MAKEFILE LINT---"
	@for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir lint; done
	@echo "---END MAKEFILE LINT---"

test:
	@# Help: Runs test stage in all subprojects
	@echo "---MAKEFILE TEST---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir test; done
	@echo "---END MAKEFILE TEST---"
	
clean:
	@# Help: Runs clean stage in all subprojects
	@echo "---MAKEFILE CLEAN---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean; done
	@echo "---END MAKEFILE CLEAN---"

clean-all:
	@# Help: Runs clean-all stage in all subprojects
	@echo "---MAKEFILE CLEAN-ALL---"
	for dir in $(SUBPROJECTS); do $(MAKE) -C $$dir clean-all; done
	@echo "---END MAKEFILE CLEAN-ALL---"


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
