#  Copyright (C) 2022 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim
COPY init-wait/entrypoint.sh /entrypoint.sh

# Install curl
RUN apt-get update && apt-get install -y --no-install-recommends curl && apt-get clean && rm -rf /var/lib/apt/lists/*

# Add a user and switch to it
USER 503

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]
