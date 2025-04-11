# Build Instructions
This document contains instructions for using `build/tpm-provider/Dockerfile` for building `tpm-provider`. The Docker
image created by the Dockerfile is referred to as `tpm-devel`.

## Rationale for 'tpm-devel' 

The `tpm-provider` currently targets RHEL8.4 and requires `tpm2-tss` to interface with the host's TPM.  Installing those packages on RHEL 8.4 will result in the following vesions of Tss2...

    tpm2-tss-2.0.0-4.el8.x86_64

Due to the dependency on Tss2, any project that includes `tpm-provider` (ex. `go-trust-agent` and `workload-agent`) will need to be built on a Linux environment with those libraries present.

While developers could build `tpm-provider` on a physical host or vm with the correct versions of Tss2, the documentation in this repository refers to the use Docker and the `tpm-devel` image.

# Building tpm-provider
## Prerequisites
* Docker
* git access to `tpm-provider`
* tpm2-tss-devel package (includes header files, link libraries, etc. needed to compile the tpm-provider)

Building, debuging and ci/cd use the `tpm-devel` image defined in build/tpm-provider/Dockerfile. It currently uses
Fedora 29 and includes tools for compiling go, c/c++, makeself, tpm2-tss etc. The image also includes the tpm-simulator.

## Compiling tpm-provider
Currently, `tpm-provider` will be statically linked into go applications (ex. `go-trust-agent`) via `go.mod` and does not need to be built independently.  However, the project does include a Makefile that compiles unit tests into `out/tpmprovider.test` (for convenience).  To compile `tpm-provider`....

1. Create a `tpm-devel` docker image...
    1. `cd cicd`
    2. `docker build --tag=tpm-devel --build-arg http_proxy=$http_proxy --build-arg https_proxy=$https_proxy --build-arg no_proxy=$no_proxy .`
    3. `docker image ls` should show `tpm-devel`
2. Start a new instance of the container, mounting the current directory as `/docker_host` directory in the container...
    1. `docker run -d --rm -v $(pwd):/docker_host -p 1443:1443 --name=tpm-devel tpm-devel tail -f /dev/null` (run this command from the root directory of your development environment so that code projects will be available in the container at '/docker_host')
    2. Configure git to access github to resolve dependencies on other ISecL go libraries.
        1. `git config --global http.proxy $http_proxy`
        2. `git config --global https.proxy $https_proxy`
        3. `git config --global url."ssh://git@github.com".insteadOf https://gitlab.com`
        4. Create ssh keys in ~/.ssh (id_rsa and id_rsa.pub)
    3. `cd /docker_host/tpm-provider`
    4. `make`
    5. `out/tpmprovider-test` executable is compiled.  All unit tests can be invoked by running `out/tmpprovider.test` or individually by running `out/tpmprovider.test -test.run TestName`.

# Unit Testing and Tpm Simulator
The `tpm-devel` docker image also contains the Microsoft TPM simulator to support debugging and unit tests.

1. Start an container of `tpm-devel`.
2. Use Docker to 'attach' to the container: ```docker exec -it tpm-devel /bin/bash```
3. Run the unit tests by either...
    a. `make` and run `out/tpmprovider.test` or...
    b. Run `go test ./...`
