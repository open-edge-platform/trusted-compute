#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

VERSION := $(shell cat VERSION)
DOCKER_REPOSITORY  ?= edge-orch/trusted-compute
DOCKER_REGISTRY    ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com

all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
	@echo "---END MAKEFILE Build---"

gen-helm:
	@# Help: generate Helm chart for cc-operator & cc-runtime
	bash ./generate_helm.sh

clean:
	@# Help: Runs clean stage in all subprojects
	rm -rf cc-operator-*.tgz
	rm -rf cc-runtimeclass*.tgz

lint:
	@# Help: Runs lint stage in all subprojects

test:
	@# Help: Runs test stage in all subprojects

coverage:
	@# Help: Runs coverage stage
	@echo "---MAKEFILE COVERAGE---"
	echo $@
	@echo "---END MAKEFILE COVERAGE---"

license: 
	## Check licensing with the reuse tool.
	reuse --version
	reuse --root . lint

docker-build:
	@echo "---MAKEFILE Docker BUILD---"
	$(MAKE) -C kata-deploy build
	@echo "---END MAKEFILE Docker Build---"

docker-push:
	$(MAKE) -C kata-deploy docker-push

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