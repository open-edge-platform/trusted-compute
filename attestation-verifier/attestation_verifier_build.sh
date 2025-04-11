#!/bin/bash  -xe
#
#  Copyright (C) 2025 Intel Corporation
#  SPDX-License-Identifier: BSD-3-Clause
#

# This is the linking script to attesation_verifier_inside_container.sh needed to invoke a docker container for the build.
# The script imports the required modules for launching debian:bookworm container for building  isecl servers
set -ex
isecl_build(){

LOCATION_OF_ISECL_REPO=$PWD
echo $LOCATION_OF_ISECL_REPO


#docker version
echo "%%%% Docker version %%%%%"
docker version

# Check if VERSION is set
if [ -z "$VERSION" ]; then
    echo "VERSION is not set. Please set the VERSION environment variable."
    exit 1
fi

#Run the docker with proxy and privileges for ubuntu:20.04 conatiner
docker run  --rm --privileged --name attestation_verifier_debian \
    -e http_proxy=${http_proxy} -e https_proxy=${https_proxy} -e VERSION=${VERSION} \
    -v /var/run/docker.sock:/var/run/docker.sock -v ${PWD}:/intel_isecl \
    -v ${PWD}/attestation_verifier_inside_container.sh:/attestation_verifier_inside_container.sh \
    -d debian:bookworm /attestation_verifier_inside_container.sh 
if  [ $? -ne 0 ]; then
	echo "Failed to run the Docker container."
	exit 1
fi
docker logs -f attestation_verifier_debian
#printing build completed container images
docker images
}

isecl_build
docker wait attestation_verifier_debian
echo " *******************DONE************************"
