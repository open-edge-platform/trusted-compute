# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

SHELL:=/bin/bash
ifndef VERSION
$(error VERSION is not set)
endif
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
PROXY_EXISTS := $(shell if [[ "${https_proxy}" || "${http_proxy}" ]]; then echo 1; else echo 0; fi)
DOCKER_PROXY_FLAGS := ""
ifeq ($(PROXY_EXISTS),1)
	DOCKER_PROXY_FLAGS = --build-arg http_proxy=${http_proxy} --build-arg https_proxy=${https_proxy}
else
	undefine DOCKER_PROXY_FLAGS
endif

init-wait: clean
	docker build ${DOCKER_PROXY_FLAGS} -t attestation-verifier/init-wait:$(VERSION) --label org.label-schema.build-date=$(BUILDDATE) -f init-wait/Dockerfile .
	#skopeo copy docker-daemon:isecl/init-wait:$(VERSION) oci-archive:init-wait/init-wait-$(VERSION).tar

nats:   clean
	docker build ${DOCKER_PROXY_FLAGS} -t attestation-verifier/nats-init:$(VERSION) --label org.label-schema.build-date=$(BUILDDATE) -f nats/Dockerfile .
	#skopeo copy docker-daemon:isecl/nats-init:$(VERSION) oci-archive:nats/nats-init-$(VERSION).tar

all: nats init-wait

clean:
	rm -rf init-wait/*.tar
	rm -rf nats/*.tar

.PHONY: all clean nats init-wait

