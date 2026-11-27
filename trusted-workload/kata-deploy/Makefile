#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

VERSION_SUFFIX              ?= ""
VERSION                     ?= $(shell cat ./VERSION)$(VERSION_SUFFIX)
DOCKER_IMAGE_NAME :=$(shell yq e '.kata-deploy.name' version.yaml)
DOCKER_REPOSITORY  ?= edge-orch/trusted-compute
DOCKER_REGISTRY    ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com
DOCKER_IMAGE       ?= ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}/${DOCKER_IMAGE_NAME}:${VERSION}
# EMT copyleft SRPM tarball emitted by the trusted-vm build that this image embeds
THIRD_PARTY_SRC_TAR  := $(realpath $(CURDIR)/../../trusted-vm)/build/trusted-vm-third-party-src.tar.gz
THIRD_PARTY_SRC_REPO ?= ${DOCKER_REPOSITORY}/${DOCKER_IMAGE_NAME}/third-party-src
THIRD_PARTY_SRC_OCI  ?= ${DOCKER_REGISTRY}/${THIRD_PARTY_SRC_REPO}:${VERSION}

all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
	VERSION=${VERSION} sudo -E bash build-kata-deploy-image.sh
	docker tag ${DOCKER_IMAGE_NAME}:${VERSION} ${DOCKER_IMAGE}
	@echo "---END MAKEFILE Build---"

clean:
	@# Help: Runs clean stage in all subprojects

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
	@# Help: Builds the docker image
	@echo "---MAKEFILE DOCKER BUILD---"
	echo $@
	@echo "---END MAKEFILE DOCKER BUILD---"
	
docker-push:
	aws ecr create-repository --region us-west-2 --repository-name ${DOCKER_REPOSITORY}/${DOCKER_IMAGE_NAME} || true
	docker push ${DOCKER_IMAGE}

artifact-publish:
	@# Help: Publishes the EMT third-party source tarball as an OCI artifact tagged like the kata-deploy image
	test -f "$(THIRD_PARTY_SRC_TAR)" || { echo "ERROR: $(THIRD_PARTY_SRC_TAR) not found; run make build first"; exit 1; }
	aws ecr create-repository --region us-west-2 --repository-name ${THIRD_PARTY_SRC_REPO} || true
	cd "$(dir $(THIRD_PARTY_SRC_TAR))" && oras push ${THIRD_PARTY_SRC_OCI} "$(notdir $(THIRD_PARTY_SRC_TAR))"

helm-build:
	@echo "This is a dummy helm-build target."

helm-push:
	@echo "This is a dummy helm-push target."

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
