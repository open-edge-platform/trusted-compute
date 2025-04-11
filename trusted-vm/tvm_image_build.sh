#!/bin/bash

#
# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

set -euo pipefail

echo "INFO: Building Trusted-VM image"

docker run --rm \
    --privileged \
    -v /dev:/dev \
    -v ${PWD}:/trusted-vm \
    ubuntu:24.04 \
    /bin/bash /trusted-vm/tvm_image_inside_container.sh

echo "INFO: Trusted-VM image built successfully"
