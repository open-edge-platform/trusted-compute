# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

SHELL:=/bin/bash
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
export VERSION := $(shell cat VERSION)
ifeq ($(PROXY_EXISTS),1)
        DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
        undefine DOCKER_PROXY_FLAGS
endif

DOCKER_REPOSITORY  ?= edge-orch/trusted-compute
DOCKER_REGISTRY    ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com
DOCKER_TARGETS = nats-init init-wait authservice cms hvs tagent aas-manager

all: build lint test
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	echo "---MAKEFILE BUILD---"
	echo "attestation-verfier build"
	sudo true  # Prompt for password once
	cd src && make download-eca
	cd utils/tools/containers/ && make all
	cd src && make docker
	echo "---END MAKEFILE Build---"

lint:
	@# Help: Runs lint stage in all subprojects

test:
	@# Help: Runs test stage in all subprojects
	cd src && go test  -v ./...

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

 
.PHONY: build all clean 
