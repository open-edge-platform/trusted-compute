#/*
# * Copyright (C) 2022 Intel Corporation
# * SPDX-License-Identifier: BSD-3-Clause
# */

FROM debian:bookworm

RUN apt-get update && \
    apt-get -yq install curl wget && \
    curl -LO https://storage.googleapis.com/kubernetes-release/release/`\
    curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt`/bin/linux/amd64/kubectl && \
    chmod +x kubectl

RUN wget -O /usr/local/bin/cfssl http://pkg.cfssl.org/R1.2/cfssl_linux-amd64 && \
    wget -O /usr/local/bin/cfssljson http://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 && \
    chmod +x /usr/local/bin/cfssl /usr/local/bin/cfssljson

RUN mkdir -p /secrets

COPY nats/nats.conf /nats.conf
COPY nats/download-tls-certs.sh /download-tls-certs.sh
COPY nats/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh && chmod +x /download-tls-certs.sh

ENTRYPOINT [ "/entrypoint.sh"]
