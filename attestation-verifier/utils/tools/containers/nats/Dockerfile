#/*
# * Copyright (C) 2022 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

# Multi-stage Dockerfile: build cfssl/cfssljson in a builder stage, copy only binaries into final image
FROM golang:1.24.7-bookworm AS builder

WORKDIR /src/cfssl

# allow optional CFSSL_TAG and KUBECTL_VER override at build time; if empty, resolve latest
ARG CFSSL_TAG
ARG KUBECTL_VER

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
    : ${KUBECTL_VER:=$(curl -fsSL https://dl.k8s.io/release/stable.txt)} && \
    curl -fsSLo /out/kubectl "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl" && \
    curl -fsSLo /out/kubectl.sha256 "https://dl.k8s.io/${KUBECTL_VER}/bin/linux/amd64/kubectl.sha256" && \
    echo "$(cat /out/kubectl.sha256)  /out/kubectl" | sha256sum -c - && \
    mkdir -p /secrets && touch /.container-env && \
    # cleanup builder apt caches
    apt-get clean && rm -rf /var/lib/apt/lists/*

# helper: collect binaries we need (bash + utilities used by the init-wait entrypoint script)
RUN set -eux; \
    mkdir -p /out/bin /out/lib /out/etc/ssl/certs; \
    cp /bin/bash /out/bin/; \
    cp /usr/bin/curl /out/bin/; \
    cp /bin/grep /out/bin/; \
    cp /usr/bin/awk /out/bin/; \
    cp /usr/bin/cut /out/bin/; \
    cp /usr/bin/sed /out/bin/; \
    cp /usr/bin/cat /out/bin/; \
    cp /usr/bin/tr /out/bin/; \
    cp /bin/sleep /out/bin/ || true; \
    # create a relative symlink 'sh' -> 'bash' so copying /out/bin to /bin yields /bin/sh -> /bin/bash
    ln -sf bash /out/bin/sh; \
    # copy ca certs
    cp -r /etc/ssl/certs /out/etc/ssl/; \
    # copy shared library dependencies for each binary found in /out/bin
    for b in /out/bin/*; do \
      ldd "$b" 2>/dev/null | awk '/=>/ {print $(NF-1)} /ld-linux/ {print $1}' | sort -u | xargs -r -I{} bash -c 'mkdir -p /out$(dirname "{}") && cp -v "{}" /out{}' ; \
    done; \
    # ensure correct perms
    chmod -R 0755 /out/bin /out/etc/ssl/certs

# Final runtime image (small, non-root, no package manager)
FROM gcr.io/distroless/base-debian12@sha256:fa15492938650e1a5b87e34d47dc7d99a2b4e8aefd81b931b3f3eb6bb4c1d2f6

# copy the cfssl binaries from builder stage (no Go runtime or sources remain)
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssl /usr/local/bin/cfssl
COPY --from=builder --chown=root:root --chmod=0755 /out/cfssljson /usr/local/bin/cfssljson
COPY --from=builder --chown=root:root --chmod=0755 /out/kubectl /usr/local/bin/kubectl
# place collected userland in /bin so /bin/bash and /bin/sh exist in the final image
COPY --from=builder /out/lib/ /lib/
COPY --from=builder /out/lib64/ /lib64/
COPY --from=builder --chmod=0755 /out/bin /bin
COPY --from=builder --chmod=0755 /secrets /secrets
COPY --from=builder --chmod=0755 /.container-env /.container-env
COPY --chmod=0755 nats/download-tls-certs.sh /download-tls-certs.sh
COPY --chmod=0755 nats/entrypoint.sh /entrypoint.sh

USER 503
ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
