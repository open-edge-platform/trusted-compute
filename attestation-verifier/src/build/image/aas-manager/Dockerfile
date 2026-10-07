#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

# Dependabot can update kubectl by tracking this image tag.
FROM registry.k8s.io/kubectl:v1.37.1@sha256:b7cab618e281b1ee7484e7b706a96e2135fbb6e072c2a573a7dab4e87d7f2385 AS kubectl

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

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