#/*
# * Copyright (C) 2022 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

# Multi-stage Dockerfile: build cfssl/cfssljson in a builder stage, copy only binaries into final image
FROM golang:1.26.2-bookworm@sha256:47ce5636e9936b2c5cbf708925578ef386b4f8872aec74a67bd13a627d242b19 AS builder

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

FROM debian:bookworm-slim@sha256:f9c6a2fd2ddbc23e336b6257a5245e31f996953ef06cd13a59fa0a1df2d5c252
ARG KUBECTL_VER

RUN set -eux; \
    apt-get update && \
    apt-get -yq install --no-install-recommends ca-certificates curl && \
    : ${KUBECTL_VER:=$(curl -fsSL https://dl.k8s.io/release/stable.txt)} && \
    curl -fsSLo /tmp/kubectl "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl" && \
    curl -fsSLo /tmp/kubectl.sha256 "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl.sha256" && \
    echo "$(cat /tmp/kubectl.sha256)  /tmp/kubectl" | sha256sum -c - && \
    install -m 0755 /tmp/kubectl /usr/local/bin/kubectl && rm -f /tmp/kubectl /tmp/kubectl.sha256 && \
    mkdir -p /secrets && touch /.container-env && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# copy the cfssl binaries from builder stage (no Go runtime or sources remain)
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssl /usr/local/bin/cfssl
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssljson /usr/local/bin/cfssljson
COPY --chmod=0755 nats/download-tls-certs.sh /download-tls-certs.sh
COPY --chmod=0755 nats/entrypoint.sh /entrypoint.sh

USER 503
ENTRYPOINT [ "/entrypoint.sh" ]
