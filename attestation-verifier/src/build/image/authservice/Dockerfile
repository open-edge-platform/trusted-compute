#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:96e378d7e6531ac9a15ad505478fcc2e69f371b10f5cdf87857c4b8188404716

LABEL org.label-schema.name="Authservice" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

RUN mkdir -p /config

COPY cmd/authservice/authservice /usr/bin/authservice
COPY build/image/authservice/entrypoint.sh /entrypoint.sh
COPY upgrades/authservice/config/* /config/
COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh
COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh

RUN apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    touch /.container-env && chmod +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

# Add a user and switch to it
USER 503

ENTRYPOINT ["/entrypoint.sh"]
