#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

COPY init-wait/entrypoint.sh /entrypoint.sh

# Install curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add a user and switch to it
USER 503

# This container is an init container (runs to completion); health checking is not applicable.
HEALTHCHECK NONE

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
