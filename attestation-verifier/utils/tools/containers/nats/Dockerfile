#/*
# * Copyright (C) 2022 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

# Multi-stage Dockerfile: build cfssl/cfssljson in a builder stage, copy only binaries into final image
FROM golang:1.26.5-bookworm@sha256:53eeac89074db483fdf0ab3be1df32bf6e47562263d2d0d6baa7f26acb4957dd AS builder

WORKDIR /src/cfssl

# allow optional CFSSL_TAG override at build time; if empty, resolve latest
ARG CFSSL_TAG
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates && \
    CFSSL_TAG="${CFSSL_TAG:-$(curl -fsSL -o /dev/null -w '%{url_effective}' https://github.com/cloudflare/cfssl/releases/latest | sed -E 's:.*/::')}" && \
    echo "Building cfssl ${CFSSL_TAG}" && \
    git clone --depth 1 --branch "${CFSSL_TAG}" https://github.com/cloudflare/cfssl.git /src/cfssl && \
    # ensure modules on and update x/crypto to latest to avoid CVEs
    go env -w GO111MODULE=on && \
    go get golang.org/x/crypto@latest && \
    go get google.golang.org/protobuf@latest && \
    go mod tidy && \
    go mod vendor && \
    # build binaries into /out
    mkdir -p /out && \
    go build -o /out/cfssl ./cmd/cfssl && \
    go build -o /out/cfssljson ./cmd/cfssljson && \
    chmod 0755 /out/cfssl /out/cfssljson && \
    # cleanup builder apt caches
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Dependabot can update kubectl by tracking this image tag.
FROM registry.k8s.io/kubectl:v1.36.3@sha256:6e4fce3c83651edb91b74bc67701c5cd263dd8aa3cd4254b1798d6425a5ab789 AS kubectl

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
COPY --from=kubectl --chmod=0755 /bin/kubectl /usr/local/bin/kubectl

RUN set -eux; \
    apt-get update && \
    apt-get -yq install --no-install-recommends ca-certificates curl && \
    mkdir -p /secrets && touch /.container-env && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# This container is an init/setup container (runs to completion); health checking is not applicable.
HEALTHCHECK NONE

# copy the cfssl binaries from builder stage (no Go runtime or sources remain)
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssl /usr/local/bin/cfssl
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssljson /usr/local/bin/cfssljson
COPY --chmod=0755 nats/download-tls-certs.sh /download-tls-certs.sh
COPY --chmod=0755 nats/entrypoint.sh /entrypoint.sh

USER 503
ENTRYPOINT [ "/entrypoint.sh" ]
