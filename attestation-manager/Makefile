#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

VERSION := $(shell cat VERSION)
DOCKER_REPOSITORY  ?= edge-orch/trusted-compute
DOCKER_REGISTRY    ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com
DOCKER_IMAGE       ?= ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}/attestation-manager:${VERSION}

## Labels to add Docker/Helm/Service CI meta-data.
LABEL_SOURCE       ?= $(shell git remote get-url $(shell git remote))
LABEL_REVISION     = $(shell git rev-parse HEAD)
LABEL_CREATED      ?= $(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

DOCKER_LABEL_ARGS  ?= \
	--build-arg org_oci_version="${VERSION}" \
	--build-arg org_oci_source="${LABEL_SOURCE}" \
	--build-arg org_oci_revision="${LABEL_REVISION}" \
	--build-arg org_oci_created="${LABEL_CREATED}"

all: 
	@# Help: Runs build, lint, test stages
	build lint test 	
	
build:
	@# Help: Runs build stage
	@echo "---MAKEFILE BUILD---"
	export GOPRIVATE="github.com/open-edge-platform/*"
	cd src/ && go mod tidy
	cd src/cmd/app && go build -o main
	docker build -f Dockerfile -t attestation-manager:${VERSION} --no-cache .
	@echo "---END MAKEFILE Build---"

clean:
	@# Help: Runs clean stage
	@echo "---MAKEFILE CLEAN---"
	rm -rf src/cmd/app/main
	rm -rf src/go.sum
	@echo "---END MAKEFILE CLEAN---"
.PHONY: docker-push
docker-push: ## Push docker images.
	aws ecr create-repository --region us-west-2 --repository-name ${DOCKER_REPOSITORY}/attestation-manager || true
	docker tag attestation-manager:${VERSION} ${DOCKER_IMAGE}
	docker push ${DOCKER_IMAGE}

.PHONY: docker-build
DOCKER_ENV := DOCKER_BUILDKIT=1
docker-build: test ## Build docker images.
	@echo "---Docker Build---"
	echo $@
	@echo "---End Docker Build---"

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

help:	
	@printf "%-20s %s\n" "Target" "Description"
	@printf "%-20s %s\n" "------" "-----------"
	@make -pqR : 2>/dev/null \
        | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
        | sort \
        | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' \
        | xargs -I _ sh -c 'printf "%-20s " _; make _ -nB | (grep -i "^# Help:" || echo "") | tail -1 | sed "s/^# Help: //g"'
	
