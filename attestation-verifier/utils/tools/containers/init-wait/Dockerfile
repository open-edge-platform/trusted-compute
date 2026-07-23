#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

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
