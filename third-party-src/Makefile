#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

# Generates tarballs of third-party source code for copyleft-licensed
# dependencies shipped in the container images (Debian) and the Trusted VM
# image (EMT, produced by trusted-vm/Makefile as build/trusted-vm-third-party-src.tar.gz).

OUT_DIR := $(shell pwd)/out

DEBIAN_BASE_IMAGE      ?= debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
# Union of packages apt-get installed by the Debian-based runtime images in this repo
DEBIAN_EXTRA_PACKAGES  ?= ca-certificates curl libtss2-esys-3.0.2-0t64
DEBIAN_TARBALL_NAME    ?= debian-trixie-third-party-src.tar.gz
COPYLEFT_LICENSE_REGEX ?= GPL|MPL|CDDL|EPL|EUPL|CeCILL|OSL

.PHONY: all debian clean help

all: debian
	@# Help: Generates all third-party source tarballs

debian:
	@# Help: Collects copyleft Debian source packages into out/$(DEBIAN_TARBALL_NAME)
	DOCKER_BUILDKIT=1 docker build \
		--no-cache \
		--target export \
		--output type=local,dest=$(OUT_DIR) \
		--build-arg http_proxy --build-arg https_proxy --build-arg no_proxy \
		--build-arg BASE_IMAGE="$(DEBIAN_BASE_IMAGE)" \
		--build-arg EXTRA_PACKAGES="$(DEBIAN_EXTRA_PACKAGES)" \
		--build-arg COPYLEFT_LICENSE_REGEX="$(COPYLEFT_LICENSE_REGEX)" \
		--build-arg TARBALL_NAME="$(DEBIAN_TARBALL_NAME)" \
		-f debian/Dockerfile debian

clean:
	@# Help: Removes generated tarballs
	rm -rf $(OUT_DIR)

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
