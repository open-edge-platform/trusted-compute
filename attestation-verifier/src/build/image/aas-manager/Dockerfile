#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

LABEL org.label-schema.name="Authservice Manager" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

COPY tools/aas-manager/populate-users /usr/bin/populate-users

# Allow optionally pinning kubectl version at build time. If not provided, resolve stable release.
ARG KUBECTL_VER

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends curl ca-certificates && \
    # determine stable kubectl version, download binary and its sha256, verify and install
    : ${KUBECTL_VER:=$(curl -fsSL https://dl.k8s.io/release/stable.txt)} && \
    curl -fsSLo kubectl "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl" && \
    curl -fsSLo kubectl.sha256 "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl.sha256" && \
    echo "$(cat kubectl.sha256)  kubectl" | sha256sum -c - && \
    install -m 0755 kubectl /usr/local/bin/kubectl && \
    chmod +x /usr/bin/populate-users && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* kubectl kubectl.sha256

# Add a user and switch to it
USER 503