#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

LABEL org.label-schema.name="Host Verification Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

COPY cmd/hvs/hvs /usr/bin/hvs
COPY build/linux/hvs/*.pem /tmp/
COPY build/linux/hvs/schema /tmp/schema
COPY build/linux/hvs/templates /tmp/templates
COPY build/image/hvs/entrypoint.sh /entrypoint.sh

RUN mkdir -p /opt/hvs/privacyca-aik-requests && \
    chmod +0766 /opt/hvs/privacyca-aik-requests && \
    chmod -R +0644 /tmp/schema /tmp/templates && \
    mkdir -p /database /config

COPY upgrades/hvs/config/* /config/
COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh
COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh
COPY upgrades/hvs/db/out/* /database/

RUN touch /.container-env && chmod -R +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

# Add a non-root user and switch to it
USER 503

ENTRYPOINT ["/entrypoint.sh"]
