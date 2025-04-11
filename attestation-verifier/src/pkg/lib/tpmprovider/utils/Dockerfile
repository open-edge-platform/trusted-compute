#--------------------------------------------------------------------------------------------------
# Copyright (C) 2020 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#--------------------------------------------------------------------------------------------------
# T P  M - D E V E L
#--------------------------------------------------------------------------------------------------
# This docker image is used for building tpm-provider as well as for gitlab pipelines.  It uses
# Fedora 29 so that the versions of tss2 will align with what is used in RHEL8.
#--------------------------------------------------------------------------------------------------
# B U I L D I N G
#--------------------------------------------------------------------------------------------------
# Create the image...
# > docker build --tag=tpm-devel --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg no_proxy=$no_proxy .
#
#   Note: This may need to be run disconnected from the proxy and without 'build-args' on Windows.
#
# Create a container, mapping the current directory to /docker_host...
# > docker run -d --rm -v $(pwd):/docker_host -v ~/.ssh:/root/.ssh --name=tpm-devel tpm-devel tail -f /dev/null
#
# Attach to the container, configure git and 'make'
# > docker exec -it tpm-devel /bin/bash
# > git config --global http.proxy $http_proxy
# > git config --global https.proxy $https_proxy
# > git config --global url."ssh://<gitlab>:<port>".insteadOf https://<gitlab>
# > git config --global user.name "user name"
# > git config --global user.email "email"
# > cd /docker_host/tpm-provider
# > make
#
#--------------------------------------------------------------------------------------------------
# T P M   S I M U L A T O R
#--------------------------------------------------------------------------------------------------
# Use the TPM simulator to run unit tests...
# - Follow the build instructions above
# > cd /docker_host/tpm-provider
# > out/tpmprovider.test -test.v
#--------------------------------------------------------------------------------------------------
FROM fedora:31

ENV container docker
ENV BASH_ENV "/root/.bashrc"
ARG http_proxy
ARG https_proxy
ARG no_proxy
ENV GOLANG_TAR=go1.18.8.linux-amd64.tar.gz

#  Install Development tools (gcc 8.3.1, ldd v2.28) tss2 and other dependencies
RUN yum -y update \
    && yum -y group install "Development Tools" \
    && yum -y install makeself gdb vim-common wget openssl-devel sudo tpm2-tools tpm2-tss-devel \
    # install go...
    && cd /tmp \
    && wget https://golang.org/dl/$GOLANG_TAR \
    && tar -C /usr/local -xzf $GOLANG_TAR \
    && rm -rf $GOLANG_TAR
    # build the tpm simulator
    && mkdir simulator \
    && cd simulator \
    && wget -O ibmtpm.tar.gz https://downloads.sourceforge.net/project/ibmswtpm2/ibmtpm1661.tar.gz \
    && tar -xavf ibmtpm.tar.gz \
    && cd src \
    && make && make install \
    # repo tool
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && ln -sf /usr/bin/pip3 /usr/bin/pip \
    && tmpdir=$(mktemp -d) \
    && git clone https://gerrit.googlesource.com/git-repo $tmpdir \
    && install -m 755 $tmpdir/repo /usr/local/bin \
    && rm -rf $tmpdir \
    # update paths, env, proxy, etc.
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc \
    && echo "export http_proxy=$http_proxy" >> ~/.bashrc \
    && echo "export https_proxy=$https_proxy" >> ~/.bashrc \
    && echo "export no_proxy=$no_proxy" >> ~/.bashrc
