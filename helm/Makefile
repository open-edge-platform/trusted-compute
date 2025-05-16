#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#/

LABEL_REVISION=$(shell git rev-parse HEAD)
LABEL_CREATED=$(shell date -u "+%Y-%m-%dT%H:%M:%SZ")

ATTESTATION_VERIFIER_VERSION     ?= $(shell cat ./../attestation-verifier/VERSION)${VERSION_SUFFIX}
ATTESTATION_MANAGER_VERSION      ?= $(shell cat ./../attestation-manager/VERSION)${VERSION_SUFFIX}
TRUSTED_WORKLOAD_VERSION        ?= $(shell cat ./../trusted-workload/VERSION)${VERSION_SUFFIX}
KATA_DEPLOY_VERSION            ?= $(shell cat ./../trusted-workload/kata-deploy/VERSION)${VERSION_SUFFIX}

HELM_REPOSITORY      ?= edge-orch/trusted-compute
HELM_REGISTRY        ?= oci://080137407410.dkr.ecr.us-west-2.amazonaws.com/
HELM_CHART_BUILD_DIR ?= build/_output/

HELM_TARGETS := attestation-manager attestation-verifier trustagent trusted-workload

all: build lint test unittest
	@# Help: Runs build, lint, test stages for all subprojects

build:
	@# Help: Runs build stage in all subprojects
	@echo "---MAKEFILE BUILD---"
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
	@echo "This is a dummy docker-build target."

docker-push: ## Push docker images.
	@echo "This is a dummy docker-push target."

.update-version-attestation-manager:
	@echo "Updating the version of attestation-manager to ${ATTESTATION_MANAGER_VERSION}"
	yq eval -i '.appVersion = "${ATTESTATION_MANAGER_VERSION}"' attestation-manager/Chart.yaml
	yq eval -i '.version = "${ATTESTATION_MANAGER_VERSION}"' attestation-manager/Chart.yaml

.update-version-attestation-verifier:
	@echo "Updating the version of attestation-verifier to ${ATTESTATION_VERIFIER_VERSION}"
	yq eval -i '.appVersion = "${ATTESTATION_VERIFIER_VERSION}"' attestation-verifier/Chart.yaml
	yq eval -i '.version = "${ATTESTATION_VERIFIER_VERSION}"' attestation-verifier/Chart.yaml
	# Find all Chart.yaml files in the specified path and update the appVersion
	find "attestation-verifier" -type f -name "Chart.yaml" | while read -r file; do \
		echo "Updating versions in $$file to ${ATTESTATION_VERIFIER_VERSION}"; \
		sed -i "s/^appVersion:.*/appVersion: ${ATTESTATION_VERIFIER_VERSION}/" "$$file"; \
		sed -i "s/^version:.*/version: ${ATTESTATION_VERIFIER_VERSION}/" "$$file"; \
		sed -i "s/^\(\s*version:\).*/\1 ${ATTESTATION_VERIFIER_VERSION}/" "$$file"; \
	done; \

.update-version-trustagent:
	@echo "Updating the version of trustagent to ${ATTESTATION_VERIFIER_VERSION}"
	yq eval -i '.appVersion = "${ATTESTATION_VERIFIER_VERSION}"' trustagent/Chart.yaml
	yq eval -i '.version = "${ATTESTATION_VERIFIER_VERSION}"' trustagent/Chart.yaml
	yq eval -i '.config.imaAllowlist |= sub("<ATTESTATION_VERIFIER_VERSION>", "${ATTESTATION_VERIFIER_VERSION}")' trustagent/values.yaml

.update-version-trusted-workload:
	@echo "Updating the version of trusted-workload to ${TRUSTED_WORKLOAD_VERSION}"
	yq eval -i '.appVersion = "${TRUSTED_WORKLOAD_VERSION}"' trusted-workload/Chart.yaml
	yq eval -i '.version = "${TRUSTED_WORKLOAD_VERSION}"' trusted-workload/Chart.yaml
	yq eval -i '.image.tag = "${KATA_DEPLOY_VERSION}"' trusted-workload/charts/cc-runtimeclass/values.yaml

helm-build-%:
	rm -rf ${HELM_CHART_BUILD_DIR}$*.tgz;
	# update the versions in the chart
	$(MAKE) .update-version-$* \

	# update the labels in the chart
	yq eval -i '.annotations.revision = "${LABEL_REVISION}"' $*/Chart.yaml; \
	yq eval -i '.annotations.created = "${LABEL_CREATED}"' $*/Chart.yaml; \

	# Build the chart
	helm package \
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
