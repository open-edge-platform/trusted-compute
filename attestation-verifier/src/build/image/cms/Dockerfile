#  Copyright (C) 2021 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause

FROM debian:bookworm

LABEL org.label-schema.name="Certificate Management Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

COPY cmd/cms/cms /usr/bin/cms

RUN mkdir -p /config

COPY upgrades/cms/config/* /config/

COPY pkg/lib/common/upgrades/container_upgrade.sh /container_upgrade.sh

COPY pkg/lib/common/upgrades/config_upgrade.sh /config_upgrade.sh

COPY build/image/cms/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh /container_upgrade.sh /config_upgrade.sh /config

ENTRYPOINT [ "/entrypoint.sh"]
