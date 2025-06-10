#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:90522eeb7e5923ee2b871c639059537b30521272f10ca86fdbbbb2b75a8c40cd

LABEL org.label-schema.name="Host Verification Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

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
