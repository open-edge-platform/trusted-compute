#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

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
