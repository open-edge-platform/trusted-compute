# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

LABEL org.label-schema.name="Trustagent Agent" \
    org.label-schema.vendor="Intel Corporation" \
    org.label-schema.license="BSD-3-Clause" \
    org.label-schema.url="https://github.com/open-edge-platform/trusted-compute"

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends libtss2-esys-3.0.2-0 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /opt/trustagent/var/system-info/ /opt/trustagent/var/ramfs /var/log/trustagent /config/

# Copy files in a single layer to reduce image size
COPY cmd/tagent/tagent /usr/bin/tagent
COPY build/image/tagent/entrypoint.sh /entrypoint.sh
COPY upgrades/tagent/config/* /config/
COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh
COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh
COPY pkg/lib/common/upgrades/config-upgrade /config-upgrade

# Set permissions in a single RUN command
RUN touch /.container-env && \
    chmod +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh && \
    chmod -R +x /config /config-upgrade

# Add a user and switch to it
USER 503

CMD ["/entrypoint.sh"]
