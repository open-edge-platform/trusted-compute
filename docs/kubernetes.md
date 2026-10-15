# Kubernetes Deployment

[Documentation home](README.md) | [Compare deployment models](deployment-options.md)

This workflow installs host attestation and the Kata VM runtime on one Ubuntu
node. K3s and existing Kubernetes share the workload steps below.

## Prerequisites

Complete the [shared prerequisites](prerequisites.md) and
[extract the release package](trusted_compute_baremetal.md).
Run installation commands from its root directory.

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

Verify existing-cluster readiness:

```bash
sudo systemctl is-active kubelet containerd
sudo kubectl get nodes
sudo kubectl get pods -A
```

Do not use `--k8s` as a general multi-node or managed-cluster installer.

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
