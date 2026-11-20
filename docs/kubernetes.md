# Kubernetes Deployment

[Documentation home](README.md) | [Compare deployment models](deployment-options.md)

This workflow installs host attestation and the Kata VM runtime on one Ubuntu
node. K3s and existing Kubernetes share the workload steps below.

## Prerequisites

### Host Platform

- Ubuntu 24.04 on an Intel x86-64 CPU with VT-x/VMX virtualization enabled in
  BIOS/UEFI and a kernel with KVM and vhost/vsock support.
- UEFI Secure Boot enabled with trusted, signed boot components. Preserve it
  when changing kernels or installing drivers; the installer checks it.
- TPM 2.0 enabled in firmware and accessible to the host for attestation.
  Provide the host measurement interfaces used by the Trust Agent, including
  IMA/securityfs for runtime measurements. Coverage depends on the active
  measurement policy.
- Supported firmware updates and a known-good baseline before enrollment.
  Record firmware and kernel versions for troubleshooting.
- At least 16 GB RAM and 128 GB storage for host services, downloaded/extracted
  artifacts, container images, logs and VMs. Increase capacity for larger or
  concurrent workloads; container limits must leave room for VM and host-service
  overhead.
- For PCIe passthrough, VT-d/IOMMU enabled in firmware and the Linux kernel,
  VFIO support and suitable IOMMU groups. Use supported devices with matching
  firmware and guest drivers; see the [GPU](trusted_compute_gpu_enablement.md),
  [NPU](trusted_compute_npu_enablement.md) and
  [SR-IOV](sriov_enablement_user_guide.md) guides for device-specific requirements.

### Software, Access and Networking

- Root/sudo access for installation and host device changes.
- `mokutil` for the installer's Secure Boot check.
- [ORAS](https://oras.land/docs/installation) and `tar` to
  [download and extract the release package](#download-the-installation-package).
- Working DNS, time synchronization and registry/network access.
- Proxy settings and registry credentials configured for the cluster runtime,
  not only the interactive shell. Keep cluster/service networks in proxy
  exclusions.
- A maintenance window and backups of existing configuration and workload
  data. Installation updates host runtime files and can restart K3s or
  containerd.

Only one Trusted Compute installation mode may own a node at a time.
Uninstall the existing mode before switching between `--k3s`, `--k8s` and
`--docker`. Docker may still be present as an image-build tool.

### Kubernetes Runtime

For **K3s**, the supplied helper installs the cluster before Trusted Compute.
The source currently pins K3s `v1.34.5+k3s1`; use the helper shipped with your
selected package. A manual K3s installation must support the package's
containerd v3 configuration.

For **existing Kubernetes**, prepare:

- A working single-node Kubernetes cluster with a configured CNI, active
  `kubelet` and `containerd` services, and containerd supporting the v3
  `io.containerd.cri.v1.runtime` configuration.
- `kubectl`, `helm`, `ctr` and [Mike Farah yq v4](https://mikefarah.gitbook.io/yq/)
  in the root user's execution path.
- Administrative cluster access for the installer. It copies
  `/etc/kubernetes/admin.conf` to root's kubeconfig if available; otherwise
  configure root's cluster access yourself.
- A schedulable node. The installer rejects the
  `node-role.kubernetes.io/control-plane:NoSchedule` taint. Remove that taint
  only on a node intentionally configured to run workloads.

Do not use `--k8s` as a general multi-node or managed-cluster installer.

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

### Option A: K3s

On a host without K3s, first run:

```bash
sudo ./k3s/k3s.sh --install
```

Then install Trusted Compute:

```bash
sudo ./install.sh --k3s
```

The installer copies charts, images and the manifest into K3s-managed
directories, writes the containerd template, creates service users and restarts
K3s. The K3s Helm controller reconciles the charts.

### Option B: Existing Kubernetes

```bash
sudo ./install.sh --k8s
```

The installer imports images into containerd's `k8s.io` namespace, configures
Kata/NRI through a containerd drop-in, restarts containerd, creates service users
and namespaces, then installs three Helm releases.

### Verify Components

Do not rely only on the installer's success message. Check the component
namespaces, device injector, runtime class and attestation result:

```bash
sudo kubectl get nodes
sudo kubectl get pods -n trusted-compute
sudo kubectl get pods -n kata-deploy
sudo kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-plugin-device-injector
sudo kubectl rollout status daemonset,deployment -n trusted-compute --timeout=600s
sudo kubectl rollout status daemonset,deployment -n kata-deploy --timeout=600s
sudo kubectl rollout status daemonset/nri-plugin-device-injector -n kube-system --timeout=600s
sudo kubectl get runtimeclass kata-qemu
sudo kubectl logs -n trusted-compute deployment/attestation-manager --tail=100
```

Expect ready long-running components, successful initialization jobs, and an
Attestation Manager report of `Overall Trust Status: true`. Investigate failures
before launching workloads; see [troubleshooting](troubleshooting.md).

## Kubernetes Components and Configuration

| Namespace | Installed components |
| --- | --- |
| `trusted-compute` | Trust Agent, AAS/CMS/HVS, databases, initialization jobs and Attestation Manager |
| `kata-deploy` | Kata deployment DaemonSet; Helm release namespace for `trusted-workload` |
| `kube-system` | NRI device injector DaemonSet created by `trusted-workload` |

The `kata-qemu` RuntimeClass is cluster-scoped. Applications must request it;
ordinary pods are not automatically converted to Trusted VMs.

| Setting | K3s | Existing Kubernetes |
| --- | --- | --- |
| Chart management | `HelmChart` resources in `kube-system` | Helm releases |
| Persistent chart configuration | `/var/lib/rancher/k3s/server/manifests/trusted-compute.yaml` | Release values supplied to `helm upgrade` |
| containerd configuration | `/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl` | `/etc/containerd/config.toml` and `/etc/containerd/conf.d/kata-qemu.toml` |
| Kata QEMU configuration | `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml` | Same path |

Both packaged Kubernetes installers override these Attestation Manager values:

```yaml
attestation-manager:
  env:
    pollDuration: 5
    InformAMServer: "false"
```

`pollDuration` is in minutes; the chart's unoverridden default is 60 minutes.
`InformAMServer: "false"` disables external status reporting, not local
attestation or Kubernetes enforcement. Keep it disabled for these standalone
workflows.

For K3s, edit `spec.valuesContent` on the `attestation-verifier` HelmChart in the
managed manifest. Do not make a competing direct Helm upgrade that the controller
will overwrite. For existing Kubernetes, save your overrides and apply them
using the matching chart from the extracted package, for example:

```bash
sudo helm upgrade attestation-verifier ./charts/attestation-verifier-*.tgz \
  --namespace trusted-compute --reuse-values \
  --set attestation-manager.env.pollDuration=5 \
  --set-string attestation-manager.env.InformAMServer=false \
  --wait --timeout 10m
```

Inspect effective values with `sudo helm get values attestation-verifier
-n trusted-compute --all`. Retain configuration backups and avoid hand-editing
generated containerd files. See [attestation flows](capabilities.md#attestation-and-security-flows)
before changing measured host files or reference flavors.

## Attestation API Reference

For administrative access to the attestation services, see the
[attestation API overview](attestation-api.md) for the service roles,
authentication flow and connection settings:

- [AAS API](aas-api.md): JWT tokens and service credentials.
- [CMS API](cms-api.md): CA certificates and certificate signing.
- [HVS API](hvs-api.md): flavors, host registration, status, reports and TPM
  endorsements.

The Attestation Manager already automates registration, reference creation and
report polling. These APIs are optional administrative interfaces, not additional
installation steps, and are not installed by the Docker workflow.

## Trusted VM Configuration

Keep the guest kernel, image and runtime configuration from the same release.
For per-workload settings, place annotations on the **pod**, or on
`spec.template.metadata.annotations` in a Deployment:

```yaml
metadata:
  annotations:
    io.katacontainers.config.hypervisor.default_memory: "2048"
spec:
  runtimeClassName: kata-qemu
```

`default_memory` is guest memory in MiB, not a Kubernetes container limit.
Set container resource requests/limits as well, and budget VM overhead. Only
annotations enabled by the installed runtime configuration are accepted.
See the [shared VM configuration guidance](capabilities.md#trusted-vm-configuration).

## Deployment and Workload Launch

Launch this basic workload before adding devices:

```bash
sudo kubectl create namespace nginx-test
sudo kubectl -n nginx-test apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: nginx-default
spec:
  runtimeClassName: kata-qemu
  containers:
    - name: nginx
      image: nginx:stable
      ports:
        - containerPort: 80
EOF
sudo kubectl wait -n nginx-test --for=condition=Ready pod/nginx-default --timeout=180s
sudo kubectl get pod nginx-default -n nginx-test -o jsonpath='{.spec.runtimeClassName}{"\n"}'
sudo kubectl logs nginx-default -n nginx-test
sudo kubectl exec -n nginx-test nginx-default -- uname -r
```

Expect `kata-qemu` and a Ready pod. The `uname` command runs in the guest;
combine it with runtime selection and host runtime diagnostics rather than
treating a process name alone as proof of attestation. Pin an approved image
digest instead of the example's mutable tag for repeatable deployments.

To test HTTP, run in one terminal:

```bash
sudo kubectl port-forward -n nginx-test pod/nginx-default 8080:80
```

In another terminal, run `curl --fail http://127.0.0.1:8080`, then stop the
port-forward with Ctrl+C. Remove the sample:

```bash
sudo kubectl delete namespace nginx-test
```

## Device, GPU and NPU Configuration

Prepare the host once using the shared device guide, then use its
**Kubernetes (K3s/K8s)** launch section:

- [Whole iGPU passthrough](trusted_compute_gpu_enablement.md)
- [NPU and companion device passthrough](trusted_compute_npu_enablement.md)
- [GPU SR-IOV virtual functions](sriov_enablement_user_guide.md)

These examples use CDI annotations and the NRI device injector, not Docker
`devices` mappings. CDI names do not reserve devices in the Kubernetes scheduler;
avoid assigning the same device to concurrent VMs.

## Uninstallation

Delete your application workloads and stop device consumers first. Back up
needed data and release device bindings using the relevant device guide.
From the retained package directory, use the matching command:

```bash
# Choose only the command for your installation:
sudo ./uninstall.sh --k3s
# Or:
sudo ./uninstall.sh --k8s
```

This removes Trusted Compute components and changes host runtime configuration;
it is not application-data backup or a general cluster teardown procedure.
The existing-Kubernetes uninstaller restores the saved pre-install containerd
configuration when available, so preserve any later intentional changes first.
