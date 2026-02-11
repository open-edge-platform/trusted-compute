#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe

COPY init-wait/entrypoint.sh /entrypoint.sh

# Install curl
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Add a user and switch to it
USER 503

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
