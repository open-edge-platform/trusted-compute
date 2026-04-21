#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

SHELL := /bin/bash
.ONESHELL:

VERSION                          ?= $(shell cat ./VERSION)
OCI_REPOSITORY                   ?= edge-orch/trusted-compute
OCI_REGISTRY                     ?= 080137407410.dkr.ecr.us-west-2.amazonaws.com
INSTALLATION_PACKAGE             ?= ${OCI_REGISTRY}/${OCI_REPOSITORY}/baremetal/trusted-compute-installation-package
ATTESTATION_VERIFIER_VERSION     ?= $(shell cat ./../attestation-verifier/VERSION)
ATTESTATION_MANAGER_VERSION      ?= $(shell cat ./../attestation-manager/VERSION)
TRUSTED_WORKLOAD_VERSION         ?= $(shell cat ./../trusted-workload/VERSION)
KATA_DEPLOY_VERSION              ?= $(shell cat ./../trusted-workload/kata-deploy/VERSION)
KATA_DEPLOY_CHART_VERSION        ?= $(shell yq -r '."kata-containers".version' ./../trusted-workload/kata-deploy/version.yaml)
KATA_DEPLOY_CHART_OCI            ?= oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy
CLUSTER_EXTENSIONS_VERSION       ?= v1.5.11
KATA_DEPLOY_VALUES_URL           ?= https://raw.githubusercontent.com/open-edge-platform/cluster-extensions/refs/tags/$(CLUSTER_EXTENSIONS_VERSION)/deployment-package/trusted-compute/values-kata-deploy-default.yaml

all: 
	@# Help: Runs build, lint, test stages
	build lint test 	
	
build:
	@# Help: Runs build stage
	@echo "---MAKEFILE BUILD---"
	set -e

	sudo true  # Prompt for password once
	PKG_NAME=trusted-compute-installation-package
	PKG_TAR=$${PKG_NAME}.tgz
	# Use a per-process staging dir to avoid permission conflicts with an
	# existing directory owned by another user/root. We need the shell PID
	# (shell $$). Makefile reduces $$$$ -> $$ when passing to the shell,
	# so use $$$$ here to ensure the shell receives the PID variable.
	STAGEDIR="$(CURDIR)/$${PKG_NAME}-staging-$$$$"
	CHARTS_DIR="$(CURDIR)/charts"
	IMAGES_DIR="$(CURDIR)/images"

	rm -rf "$$STAGEDIR" || true
	mkdir -p "$$STAGEDIR"/charts "$$STAGEDIR"/containerd "$$STAGEDIR"/images "$$STAGEDIR"/k3s "$$STAGEDIR"/manifests

	# Copy existing files from repo
	cp -a "$(CURDIR)/install.sh" "$$STAGEDIR/"
	cp -a "$(CURDIR)/uninstall.sh" "$$STAGEDIR/"
	cp -a "$(CURDIR)/k3s.sh" "$$STAGEDIR/k3s/k3s.sh"
	cp -a "$(CURDIR)/trusted-compute.yaml" "$$STAGEDIR/manifests/trusted-compute.yaml"

	# Create docker directory and copy tw-docker-deploy.yaml, updating image and version
	mkdir -p "$$STAGEDIR/docker"
	cp -a "$(CURDIR)/tw-docker-deploy.yaml" "$$STAGEDIR/docker/tw-docker-deploy.yaml"
	sed -i 's|\(image:.*kata-deploy:\)[^[:space:]]*|\1$(KATA_DEPLOY_VERSION)|g' "$$STAGEDIR/docker/tw-docker-deploy.yaml"

	# Replace hardcoded chart versions in the staged manifest with Makefile vars using sed
	sed -i \
		-e 's/attestation-verifier\.tgz/attestation-verifier-$(ATTESTATION_VERIFIER_VERSION).tgz/g' \
		-e 's/trusted-workload\.tgz/trusted-workload-$(TRUSTED_WORKLOAD_VERSION).tgz/g' \
		-e 's/kata-deploy\.tgz/kata-deploy-$(KATA_DEPLOY_CHART_VERSION).tgz/g' \
		"$$STAGEDIR/manifests/trusted-compute.yaml"

	# Patch kata-deploy valuesContent from external values YAML
	KATA_DEPLOY_VALUES_FILE="$$STAGEDIR/manifests/values-kata-deploy-default.yaml"
	curl -fsSL "$(KATA_DEPLOY_VALUES_URL)" -o "$$KATA_DEPLOY_VALUES_FILE"
	yq -i '(select(.kind == "HelmChart" and .metadata.name == "kata-deploy").spec.valuesContent) = load_str("'"$$KATA_DEPLOY_VALUES_FILE"'")' "$$STAGEDIR/manifests/trusted-compute.yaml"
	rm -f "$$KATA_DEPLOY_VALUES_FILE"

	# Update kata-deploy image tag in the trusted-compute.yaml manifest to match KATA_DEPLOY_VERSION
	sed -i 's|\(tag: "\)[^"]*\("\)|\1$(KATA_DEPLOY_VERSION)\2|g' "$$STAGEDIR/manifests/trusted-compute.yaml"

	cp -a "$(CURDIR)/config-v3.toml.tmpl" "$$STAGEDIR/containerd/config-v3.toml.tmpl"

	# Readme points to docs/trusted_compute_baremetal.md
	if [ -f "$(CURDIR)/../docs/trusted_compute_baremetal.md" ]; then
		cp "$(CURDIR)/../docs/trusted_compute_baremetal.md" "$$STAGEDIR/readme.md"
	else
		printf "See docs/trusted_compute_baremetal.md in repository" > "$$STAGEDIR/readme.md"
	fi

	# Ensure helm charts are built and available in the helm output
	@echo "Building helm charts (../helm helm-build)"
	set -e; make -C "$(CURDIR)/../helm" helm-build

	# Copy generated charts from helm/build/_output to staging charts folder if present
	if [ -d "$(CURDIR)/../helm/build/_output" ]; then \
		cp -a "$(CURDIR)/../helm/build/_output/." "$$STAGEDIR"/charts/; \
	fi

	# Pull kata-deploy chart from OCI into the staged charts directory
	@echo "Pulling kata-deploy chart $(KATA_DEPLOY_CHART_OCI):$(KATA_DEPLOY_CHART_VERSION)"
	helm pull "$(KATA_DEPLOY_CHART_OCI)" --version "$(KATA_DEPLOY_CHART_VERSION)" --destination "$$STAGEDIR/charts"

	# Pull and export images to staging images folder
	# List of images to pull and export
	IMAGES="registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-manager:$(ATTESTATION_MANAGER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/aas-manager:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/authservice:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/cms:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/hvs:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/init-wait:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/nats-init:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/attestation-verifier/tagent:$(ATTESTATION_VERIFIER_VERSION) \
	registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/kata-deploy:$(KATA_DEPLOY_VERSION)"

	printf "Attempting to populate images into staging: %s\n" "$$STAGEDIR/images"; \
	mkdir -p "$$STAGEDIR/images"; \
	set -x
	for image in $$IMAGES; do \
		printf "Processing: %s\n" "$$image"; \
		if sudo ctr image pull "$$image"; then \
			safe_name=$$(echo "$$image" | sed 's#[/:]#-#g'); \
			tar_file="$$STAGEDIR/images/$${safe_name}.tar"; \
			if sudo ctr image export "$$tar_file" "$$image"; then \
				printf "✓ Exported: %s\n" "$$tar_file"; \
			else \
				printf "✗ Failed to export: %s\n" "$$image" >&2 || true; \
			fi; \
		else \
			printf "✗ Failed to pull: %s\n" "$$image" >&2 || true; \
		fi; \
	done

	# create final gzipped tarball in the baremetal directory
	tar -C "$$STAGEDIR" --transform "s,^,$${PKG_NAME}/," -czf "$(CURDIR)/$${PKG_TAR}" .
	echo "Created $(CURDIR)/$${PKG_TAR}"
	rm -rf "$$STAGEDIR" || true
	@echo "---END MAKEFILE Build---"

clean:
	@# Help: Runs clean stage
	@echo "---MAKEFILE CLEAN---"
	@echo "---END MAKEFILE CLEAN---"

.PHONY: docker-push
docker-push:
	@echo "This is a dummy docker-push target"
.PHONY: docker-build
docker-build:
	@echo "This is a dummy docker-build target"

helm-build:
	@echo "This is a dummy helm-build target."

helm-push:
	@echo "This is a dummy helm-push target."

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

artifact-publish:
	@echo "Publishing trusted-compute-installation-package.tgz to Production Release Service."
	aws ecr create-repository --region us-west-2 --repository-name ${OCI_REPOSITORY}/baremetal/trusted-compute-installation-package || true
	oras push $(INSTALLATION_PACKAGE):$(VERSION) ./trusted-compute-installation-package.tgz

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
	
