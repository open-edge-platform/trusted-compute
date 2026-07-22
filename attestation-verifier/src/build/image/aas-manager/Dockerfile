#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

# Dependabot can update kubectl by tracking this image tag.
FROM registry.k8s.io/kubectl:v1.36.2@sha256:b0d792e0d8dfb9bb1b922b78b23137e2a34bb6f9667640353a9d2aadd1fd7761 AS kubectl

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

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