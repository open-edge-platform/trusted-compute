# Trusted Workload with Docker - User Guide

This guide provides step-by-step instructions for installing the trusted workload which uses Kata Containers for Docker, and running sample workloads such as NGINX.

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installing Trusted Workload for Docker](#2-installing-trusted-workload-for-docker)
3. [Running Sample Workloads](#3-running-sample-workloads)
   - [NGINX Sample Workload](#nginx-sample-workload)
4. [Uninstalling Trusted Workload](#4-uninstalling-trusted-workload)
5. [Troubleshooting](#5-troubleshooting)

## 1. Prerequisites

Before setting up trusted workloads, ensure you have:

- Docker Engine installed and the Docker service running.
- The `containerd` service running (automatically included with Docker).
- Docker Compose plugin installed and available.

## 2. Installing Trusted Workload for Docker

The trusted workload can be set up for Docker using Docker Compose with the following command:

Download [tw-docker-deploy.yaml](https://github.com/open-edge-platform/trusted-compute/blob/main/trusted-workload/kata-deploy/tw-docker-deploy.yaml).

```bash
VERSION=1.4.9 docker compose -f tw-docker-deploy.yaml up -d
```

This command deploys the `tc-docker-deploy` container, which automates the installation and configuration of Kata Containers on your host system. The container performs the following:

- Copies Kata runtime binaries to `/opt/kata`
- Copies the containerd shim binary to `/usr/bin/containerd-shim-kata-v2`
- Creates the Kata configuration file at `/etc/kata-containers/configuration.toml`
- Stays running, waiting for cleanup signal

## 3. Running Sample Workloads

Once the trusted workload is set up, you can run containers using the Kata Containers runtime.

### NGINX Sample Workload

You can run an NGINX container with the Kata runtime:

1. Run NGINX with the Kata runtime:
   ```bash
   docker run -d --name nginx-trusted-workload \
     --runtime io.containerd.kata.v2 \
     -p 80:80 \
     nginx:1.27.0
   ```

2. Verify the container is running:
   ```bash
   docker ps | grep nginx-trusted-workload
   ```

3. Verify it's using Kata runtime:
   ```bash
   docker inspect nginx-trusted-workload --format '{{.HostConfig.Runtime}}'
   ```
   Output should be: `io.containerd.kata.v2`

4. To stop and remove the container:
   ```bash
   docker stop nginx-trusted-workload
   docker rm nginx-trusted-workload
   ```

**Note:** To use Kata runtime with Docker Compose, simply add `runtime: io.containerd.kata.v2` to your service definition in the compose file.

## 4. Uninstalling Trusted Workload

To remove the trusted workload, use the following command:

```bash
VERSION=1.4.9 docker compose -f tw-docker-deploy.yaml down
```

The `tc-docker-deploy` container automatically performs cleanup on shutdown:

- Removes `/opt/kata` directory and all contents
- Removes `/usr/bin/containerd-shim-kata-v2` binary
- Removes `/etc/kata-containers/configuration.toml` file
- Removes `/etc/kata-containers` directory if empty


## 5. Troubleshooting

1. **Runtime not found error**: If you see an error like `unknown runtime specified: io.containerd.kata.v2`, ensure that:
   - The Kata deployment completed successfully: `docker ps | grep kata-deploy`
   - Check deployment logs: `docker logs kata-deploy`
   - Verify Kata files exist:
     ```bash
     ls -la /usr/bin/containerd-shim-kata-v2
     ls -la /etc/kata-containers/configuration.toml
     ```

2. **Container fails to start**: Check the logs:
   ```bash
   docker logs kata-deploy
   ```
   Look for ERROR or WARN messages indicating what failed.