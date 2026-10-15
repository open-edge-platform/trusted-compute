# Docker/Container-Based Deployment

[Documentation home](README.md) | [Compare deployment models](deployment-options.md)

This workflow installs Kata-based VM isolation without Kubernetes. It does not
install host attestation services or automatic trust-based workload enforcement.

## Prerequisites

### Host Platform

- Ubuntu 24.04 on an Intel x86-64 CPU with VT-x/VMX virtualization enabled in
  BIOS/UEFI and a kernel with KVM and vhost/vsock support.
- UEFI Secure Boot enabled with trusted, signed boot components. Preserve it
  when changing kernels or installing drivers; the installer checks it.
- Supported firmware updates and a known-good host baseline. Record firmware
  and kernel versions for troubleshooting.
- At least 16 GB RAM and 128 GB storage for host services, downloaded/extracted
  artifacts, container images, logs and VMs. Increase capacity for larger or
  concurrent workloads; container limits must leave room for VM and host-service
  overhead.
- For PCIe passthrough, VT-d/IOMMU enabled in firmware and the Linux kernel,
  VFIO support and suitable IOMMU groups. Use supported devices with matching
  firmware and guest drivers; see the [GPU](trusted_compute_gpu_enablement.md),
  [NPU](trusted_compute_npu_enablement.md) and
  [SR-IOV](sriov_enablement_user_guide.md) guides for device-specific requirements.

This mode does not install host attestation services, so the Kubernetes TPM
and IMA/securityfs prerequisites do not apply.

### Software, Access and Networking

- Root/sudo access for installation and host device changes.
- `mokutil` for the installer's Secure Boot check.
- [ORAS](https://oras.land/docs/installation) and `tar` to
  [download and extract the release package](#download-the-installation-package).
- Working DNS, time synchronization and registry/network access. Packaged
  images do not guarantee an air-gapped deployment: workload images and initial
  Docker installation can need network access.
- Proxy settings and registry credentials configured for Docker, not only
  the interactive shell.
- A maintenance window and backups of existing configuration and workload
  data. Installation updates host runtime files.

Only one Trusted Compute installation mode may own a node at a time.
Uninstall an existing `--k3s` or `--k8s` Trusted Compute installation before
switching to `--docker`. This restriction does not prohibit Docker's presence
as an image-build tool.

### Docker Runtime

Install:

- [Docker Engine for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- [Docker Compose v2 plugin](https://docs.docker.com/compose/install/linux/)

Use a rootful Docker daemon: the deployment container installs host binaries and
configuration using privileged mounts. Rootless Docker is not this workflow.
For device/VM annotations, use Compose with support for the service `annotations`
field (Compose 2.26.0 or later).

See the [package compatibility note](trusted_compute_baremetal.md) if using
Trusted Compute 1.5.0 through 1.5.2.

## Download the Installation Package

Choose a published release and download it into an empty working directory:

```bash
VERSION=1.5.3
oras pull "registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package:${VERSION}"
tar -xvf trusted-compute-installation-package.tgz
cd trusted-compute-installation-package
```

`1.5.3` is an example release, not a floating "latest" tag. To list available
versions before choosing:

```bash
oras repo tags registry-rs.edgeorchestration.intel.com/edge-orch/trusted-compute/baremetal/trusted-compute-installation-package
```

Run the installation commands below from the extracted package's root directory
and keep it for configuration and uninstallation. Use the packaged installer,
not a copied standalone script from the repository: package creation fills in
component versions and includes the required artifacts. See the
[package layout](trusted_compute_baremetal.md#package-layout) for its contents.

## Installation

Run from the extracted package directory:

```bash
sudo ./install.sh --docker
sudo docker compose -f docker/tw-docker-deploy.yaml ps
sudo docker logs kata-deploy
sudo test -x /usr/bin/containerd-shim-kata-v2
sudo test -f /etc/kata-containers/configuration.toml
```

The installer loads the packaged `kata-deploy` image and starts it using Compose.
The container extracts runtime artifacts to `/opt/kata`, installs the shim in
`/usr/bin`, copies configuration into `/etc/kata-containers`, and stays running.
Look for `Installation complete` in its logs, then verify the workload below.

**Keep `kata-deploy` running.** On normal termination it cleans up installed
runtime artifacts. It is not an application container that can be removed after
setup. Do not stop it while Kata workloads are running.

## Container Configuration

The package's `docker/tw-docker-deploy.yaml` configures the **runtime installer**,
not your application:

| Setting | Meaning |
| --- | --- |
| `privileged: true` | Host installation privileges for `kata-deploy` |
| `/opt`, `/usr/bin`, `/etc` host mounts | Destination locations for runtime artifacts |
| `network_mode: none` | Installer container needs no application networking |
| `DEBUG=false` | Installer log verbosity |
| `restart: unless-stopped` | Keep the runtime installer container available |

Do not copy these privileged installer settings into ordinary application
containers. Create a separate Compose file for applications and select
`io.containerd.kata.v2` explicitly. The normal Docker default runtime remains
separate.

## Trusted VM Configuration

The Docker deployment copies the default Kata configuration to
`/etc/kata-containers/configuration.toml`. Keep it aligned with the installed
guest artifacts. Restarting/recreating `kata-deploy` can replace that copy.
Prefer supported per-container annotations for workload-specific settings.

For example, in an application Compose service:

```yaml
runtime: io.containerd.kata.v2
annotations:
  io.katacontainers.config.hypervisor.default_memory: "2048"
```

Guest memory is expressed in MiB and differs from container resource limits.
See the [common VM configuration guidance](capabilities.md#trusted-vm-configuration).
Pod `runtimeClassName` and NRI/CDI pod annotations are not Docker configuration.

## Deployment and Workload Launch

### Docker CLI

```bash
sudo docker run -d --name nginx-test \
  --runtime io.containerd.kata.v2 \
  -p 127.0.0.1:8080:80 nginx:stable
sudo docker inspect nginx-test --format '{{.HostConfig.Runtime}}'
sudo docker ps --filter name=nginx-test
sudo docker logs nginx-test
sudo docker exec nginx-test uname -r
curl --fail --retry 10 --retry-connrefused --retry-delay 2 http://127.0.0.1:8080
```

Expect runtime `io.containerd.kata.v2`, a running container, and an nginx HTTP
response. `uname` runs in the guest, not directly on the host. These checks
demonstrate the launch path; they do not constitute an attestation result.
Use approved image digests rather than mutable tags in production.

Stop and remove the sample before using the Compose alternative:

```bash
sudo docker stop nginx-test
sudo docker rm nginx-test
```

### Docker Compose

Create an application file named `nginx.yaml`:

```yaml
services:
  nginx:
    image: nginx:stable
    runtime: io.containerd.kata.v2
    annotations:
      io.katacontainers.config.hypervisor.default_memory: "2048"
    ports:
      - "127.0.0.1:8080:80"
```

Validate, launch and check it:

```bash
sudo docker compose -f nginx.yaml config --quiet
sudo docker compose -f nginx.yaml up -d
sudo docker compose -f nginx.yaml ps
sudo docker compose -f nginx.yaml logs nginx
sudo docker inspect "$(sudo docker compose -f nginx.yaml ps -q nginx)" \
  --format '{{.HostConfig.Runtime}}'
curl --fail --retry 10 --retry-connrefused --retry-delay 2 http://127.0.0.1:8080
sudo docker compose -f nginx.yaml down
```

The example binds only to localhost. For remote access, explicitly choose an
appropriate host interface, firewall rules and application authentication.

## Device, GPU and NPU Configuration

Use the common host preparation, then the **Docker Compose** section in:

- [GPU passthrough](trusted_compute_gpu_enablement.md)
- [NPU passthrough](trusted_compute_npu_enablement.md)
- [GPU SR-IOV](sriov_enablement_user_guide.md)

The Docker examples pass the host's `/dev/vfio/<group>` devices and specify
hypervisor annotations. Replace group numbers with the actual binding-script
output; do not copy a Kubernetes CDI annotation into Docker.

## Uninstallation

Stop and remove application containers, including device consumers, first.
Restore device bindings using the appropriate device guide. Then, from the
retained installation package:

```bash
sudo ./uninstall.sh --docker
```

This stops/removes `kata-deploy`; its termination cleanup removes the installed
runtime artifacts. It does not uninstall Docker Engine or back up application
data. See [troubleshooting](troubleshooting.md) if the runtime is unavailable
after an installer-container restart or interrupted removal.
