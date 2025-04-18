#  Copyright (C) 2021 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm

LABEL org.label-schema.name="Authservice" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/authservice/authservice /usr/bin/authservice

COPY build/image/authservice/entrypoint.sh /entrypoint.sh

RUN mkdir -p /config

COPY upgrades/authservice/config/* /config/

COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh

COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh

RUN touch /.container-env && chmod +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

# Add a user and switch to it
USER 503

ENTRYPOINT ["/entrypoint.sh"]
