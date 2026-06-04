#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

LABEL org.label-schema.name="Certificate Management Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

RUN mkdir -p /config

COPY cmd/cms/cms /usr/bin/cms
COPY upgrades/cms/config/* /config/
COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh
COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh
COPY build/image/cms/entrypoint.sh /entrypoint.sh

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    touch /.container-env && chmod +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

# Add a user and switch to it
USER 503

ENTRYPOINT [ "/entrypoint.sh"]
