#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:67b30a61dc87758f0caf819646104f29ecbda97d920aaf5edc834128ac8493d3

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
