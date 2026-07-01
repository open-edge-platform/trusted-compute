#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

# Dependabot can update kubectl by tracking this image tag.
FROM registry.k8s.io/kubectl:v1.36.1@sha256:d08f476d04d0e30f426f06bc6ff6c38913aaa4591943046b77e2f74a72d3611c AS kubectl

FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

LABEL org.label-schema.name="Authservice Manager" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

COPY tools/aas-manager/populate-users /usr/bin/populate-users
COPY --chmod=0755 --from=kubectl /bin/kubectl /usr/local/bin/kubectl

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    chmod +x /usr/bin/populate-users && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add a user and switch to it
USER 503