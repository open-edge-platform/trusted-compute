#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

LABEL_REVISION=$(shell git rev-parse HEAD)
LABEL_CREATED=$(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

HELM_REPOSITORY      ?= edge-orch/trusted-compute
HELM_REGISTRY        ?= oci://080137407410.dkr.ecr.us-west-2.amazonaws.com/
HELM_CHART_BUILD_DIR ?= build/_output/

HELM_TARGETS := attestation-manager attestation-verifier trustagent trusted-workload

all: build lint test unittest
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
	@echo "Trusted-worklaod build"
	@echo "---END MAKEFILE Build---"

clean:
	@# Help: Runs clean stage in all subprojects
	rm -rf helm-unittest-output.xml
	rm -rf lint_report.txt
	bash ./helm_lint.sh clean

lint: yaml-lint helm-lint
	@# Help: Runs lint stage in all subprojects

yaml-lint:
	@# Help: Runs lint stage in all subprojects
	@echo "---MAKEFILE YAML LINT---"
	bash ./lint_yaml.sh
	@echo "---END MAKEFILE YAML LINT---"

unittest:
	@# Help: Runs unit test stage in all subprojects
	@echo "---MAKEFILE UNITTEST---"
	bash ./helm_unittest.sh
	@echo "---END MAKEFILE UNITTEST---"

test: unittest
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

list: 
	@# Help: displays make targets
	help

docker-build:
	@echo "---Docker Build---"
	echo "add docker build -f Dockerfile -t <image name version> --no-cache <folder"
	@echo "---End Docker Build---"

docker-push: ## Push docker images.
	@echo "----------Docker push images-------"
	echo "docker push ${DOCKER_IMAGE}"

helm-build-%:
	rm -rf ${HELM_CHART_BUILD_DIR}$*.tgz;
	if [ "$*" = "attestation-manager" ]; then \
		yq eval -i '.appVersion = "$(shell cat ../attestation-manager/VERSION)"' $*/Chart.yaml; \
	elif [ "$*" = "attestation-verifier" ]; then \
		bash ./updateAppVersion.sh attestation-verifier; \
	elif [ "$*" = "trustagent" ]; then \
		yq eval -i '.appVersion = "$(shell cat ../attestation-verifier/VERSION)"' $*/Chart.yaml; \
		yq eval -i '.config.imaAllowlist |= sub("\\{VERSION\\}", "$(shell cat ../attestation-verifier/VERSION)")' trustagent/values.yaml; \
	fi;

	yq eval -i '.version = "$(shell cat ./$*/VERSION)"' $*/Chart.yaml;
	yq eval -i '.annotations.revision = "${LABEL_REVISION}"' $*/Chart.yaml;
	yq eval -i '.annotations.created = "${LABEL_CREATED}"' $*/Chart.yaml;
	helm package \
		--version=$(shell cat ./$*/VERSION) \
		--dependency-update \
		--destination ${HELM_CHART_BUILD_DIR} \
		$*

helm-lint:
	@# Help: Runs helm lint stage for all specified targets
	@echo "---MAKEFILE HELM LINT---"
	bash ./helm_lint.sh
	@echo "---END MAKEFILE HELM LINT---"

helm-push-%:
	aws ecr create-repository --region us-west-2 --repository-name $(HELM_REPOSITORY)/charts/$* || true
	helm push ${HELM_CHART_BUILD_DIR}$*-*.tgz $(HELM_REGISTRY)${HELM_REPOSITORY}/charts

helm-build: $(addprefix helm-build-,$(HELM_TARGETS))
	@# Help: Runs helm build stage for all specified targets

helm-push: $(addprefix helm-push-,$(HELM_TARGETS))
	@# Help: Runs helm push stage for all specified targets

helm-build-clean:
	@# Help: Cleans helm build directory
	rm -rf ${HELM_CHART_BUILD_DIR}*
	for target in $(HELM_TARGETS); do \
		yq eval -i 'del(.annotations.revision)' ./$$target/Chart.yaml; \
		yq eval -i 'del(.annotations.created)' ./$$target/Chart.yaml; \
	done

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
