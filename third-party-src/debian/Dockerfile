# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

# Collects copyleft-licensed Debian source packages for the runtime images in
# this repo. BASE_IMAGE must match the base used by those images and
# EXTRA_PACKAGES the union of packages they apt-get install.
ARG BASE_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

FROM ${BASE_IMAGE} AS collector

ARG EXTRA_PACKAGES=""
ARG COPYLEFT_LICENSE_REGEX
ARG TARBALL_NAME

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    if [ -n "${EXTRA_PACKAGES}" ]; then \
        apt-get install -y --no-install-recommends ${EXTRA_PACKAGES}; \
    fi

COPY --chmod=0755 collect_debian_sources.sh /collect_debian_sources.sh
RUN OUT_DIR=/out /collect_debian_sources.sh

FROM scratch AS export
COPY --from=collector /out/ /
