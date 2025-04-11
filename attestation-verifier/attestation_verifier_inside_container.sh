#!/bin/bash
#
#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause
#


#This script will install required libraries for isecl build inside container
#It will build isecl packages and import them as docker images

# Check if build parameter is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <build_param>"
    exit 1
fi

BUILD_PARAM=$1

#Installing Pre-requisites
set -ex
apt update &> /dev/null
apt  install  -y \
    curl \
    wget &> /dev/null


apt update
apt install -y  git wget tar python3 gcc-11 make makeself openssl libssl-dev libgpg-error-dev &> /dev/null

cp /usr/bin/gcc-11 /usr/bin/gcc

ln -s /usr/bin/python3 /usr/bin/python
ln -s /usr/bin/pip3 /usr/bin/pip


#Installing go
wget https://dl.google.com/go/go1.18.8.linux-amd64.tar.gz  &> /dev/null
if  [ $? -ne 0 ]; then
    echo "Failed to download the go package"
    exit 1
fi
tar -xzf go1.18.8.linux-amd64.tar.gz
mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOROOT/bin:$PATH
rm -rf go1.18.8.linux-amd64.tar.gz

apt update &> /dev/null
apt  install -y \
    ca-certificates \
    gnupg \
    lsb-release &> /dev/null

# Add Docker's official GPG key:
 apt-get update
 install -m 0755 -d /etc/apt/keyrings
 curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
 if  [ $? -ne 0 ]; then
    echo "Failed to download the Docker GPG key."
    exit 1
fi
 chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
   tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tzdata \

apt-cache policy docker-ce
apt install -y docker-ce 
apt-get install -y libtss2-dev
apt install -y cabextract
apt-get -y install skopeo

git config --global --add safe.directory /intel_isecl
git config --global --add safe.directory /intel_isecl/src/intel-secl

cd /intel_isecl/

echo "************* Executing make command**************"

if [ "$BUILD_PARAM" == "build" ]; then
    make -f Makefile_isecl k8s
elif [ "$BUILD_PARAM" == "test" ]; then
    cd src/
    go test  -v ./...
fi

echo "************* completed make command**************"
