# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

SHELL:=/bin/bash
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
VERSION := $(shell cat VERSION)
ifeq ($(PROXY_EXISTS),1)
        DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
        undefine DOCKER_PROXY_FLAGS
endif

DOCKER_REPOSITORY  ?= edge-orch/trusted-compute
DOCKER_REGISTRY    ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com
DOCKER_TARGETS = nats-init init-wait authservice cms hvs tagent aas-manager

DOCKER_IMAGE = debian:bookworm
CONTAINER_NAME = attestation_verifier_debian
CONTAINER_NAME_TEST = attestation_verifier_debian_test
VERFIER_DIR_NAME = attestation-verifier
VERIFIER_PATH =   $(shell find $(PWD) -maxdepth 1 -type d -name $(VERFIER_DIR_NAME) -print -quit)
SCRIPT_PATH = $(VERIFIER_PATH)/attestation_verifier_inside_container.sh

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/


all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	echo "---MAKEFILE BUILD---"
	echo "attestation-verfier build"
	sudo true  # Prompt for password once

	@if [ "$(shell docker ps -q -f name=$(CONTAINER_NAME))" ]; then \
		echo "Error: Container '$(CONTAINER_NAME)' is already running."; \
		exit 1; \
	else \
		echo "Starting container '$(CONTAINER_NAME)'..."; \
		echo '$(SCRIPT_PATH)';\
		echo '$(VERIFIER_PATH)';\
		docker run --rm --privileged --name $(CONTAINER_NAME) \
			-e http_proxy=${http_proxy} -e https_proxy=${https_proxy} -e VERSION=${VERSION} \
			-v /var/run/docker.sock:/var/run/docker.sock -v ${VERIFIER_PATH}:/intel_isecl \
			-v $(SCRIPT_PATH):/attestation_verifier_inside_container.sh \
			-d $(DOCKER_IMAGE) /attestation_verifier_inside_container.sh build; \
		docker logs -f $(CONTAINER_NAME); \
		docker images; \
	fi
	echo "---END MAKEFILE Build---"


lint:
	@# Help: Runs lint stage in all subprojects

test:
	@# Help: Runs test stage in all subprojects
	@if [ "$(shell docker ps -q -f name=$(CONTAINER_NAME_TEST))" ]; then \
		echo "Error: Container '$(CONTAINER_NAME_TEST)' is already running."; \
		exit 1; \
	else \
		echo "Starting container '$(CONTAINER_NAME_TEST)'..."; \
		echo '$(SCRIPT_PATH)';\
		echo '$(VERIFIER_PATH)';\
		docker run --rm --privileged --name $(CONTAINER_NAME_TEST) \
			-e http_proxy=${http_proxy} -e https_proxy=${https_proxy} -e VERSION=${VERSION} \
			-v /var/run/docker.sock:/var/run/docker.sock -v ${VERIFIER_PATH}:/intel_isecl \
			-v $(SCRIPT_PATH):/attestation_verifier_inside_container.sh \
			-d $(DOCKER_IMAGE) /attestation_verifier_inside_container.sh test; \
		docker logs -f $(CONTAINER_NAME_TEST); \
		docker images; \
	fi

coverage:
	@# Help: Runs coverage stage
	@echo "---MAKEFILE COVERAGE---"
	echo $@
	@echo "---END MAKEFILE COVERAGE---"

license:
	## Check licensing with the reuse tool.
	reuse --version
	reuse --root . lint

list:
	@# Help: displays make targets
	help

docker-build:
	@echo "---Docker Build---"
	echo "add docker build -f Dockerfile -t <image name version> --no-cache <folder"
	@echo "---End Docker Build---"

docker-push-%:
	@echo "---Docker Push for $*---"
	aws ecr create-repository --region us-west-2 --repository-name ${DOCKER_REPOSITORY}/attestation-verifier/$* || true
	docker tag attestation-verifier/$*:$(VERSION) ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}/attestation-verifier/$*:$(VERSION)
	docker push ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}/attestation-verifier/$*:$(VERSION)
	@echo "---End Docker Push for $*---"

docker-push: $(addprefix docker-push-,$(DOCKER_TARGETS))
clean:
	@# Help: Runs clean stage in all subprojects
	rm -rf k8s/
	rm -rf src/cmd/authservice/authservice
	rm -rf  src/cmd/cms/cms
	rm -rf src/cmd/hvs/hvs
	rm -rf src/cmd/tagent/tagent
	rm -rf src/deployments/container-archive/oci/aas-manager-v5.1.0-.tar
	rm -rf src/deployments/container-archive/oci/authservice-v5.1.0-.tar
	rm -rf src/deployments/container-archive/oci/cms-v5.1.0-.tar
	rm -rf src/deployments/container-archive/oci/hvs-v5.1.0-.tar
	rm -rf src/deployments/container-archive/oci/tagent-v5.1.0-.tar
	rm -rf src/deployments/installer/populate-users.sh
	rm -rf src/go.sum
	rm -rf src/tools/aas-manager/populate-users
	rm -rf src/upgrades/hvs/db/out/
	rm -rf utils/tools/containers/db-version-upgrade/db-version-upgrade-v11-v14.tar
	rm -rf utils/tools/containers/init-wait/init-wait-v5.1.0.tar
	rm -rf utils/tools/containers/nats/nats-init-v5.1.0.tar
 
.PHONY: build all clean 
