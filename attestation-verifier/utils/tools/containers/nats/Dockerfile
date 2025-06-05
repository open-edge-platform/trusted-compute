#/*
# * Copyright (C) 2022 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM debian:bookworm-slim@sha256:90522eeb7e5923ee2b871c639059537b30521272f10ca86fdbbbb2b75a8c40cd

COPY nats/nats.conf /nats.conf
COPY nats/download-tls-certs.sh /download-tls-certs.sh
COPY nats/entrypoint.sh /entrypoint.sh

RUN apt-get update && \
    apt-get -yq install --no-install-recommends curl ca-certificates wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    curl -LO https://dl.k8s.io/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl && \
    chmod +x kubectl && \
    wget -O /usr/local/bin/cfssl http://pkg.cfssl.org/R1.2/cfssl_linux-amd64 && \
    wget -O /usr/local/bin/cfssljson http://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 && \
    chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson && \
    mkdir -p /secrets && \
    touch /.container-env && \
    chmod +x /entrypoint.sh && \
    chmod +x /download-tls-certs.sh

# Add a user and switch to it
USER 503

ENTRYPOINT [ "/entrypoint.sh"]
