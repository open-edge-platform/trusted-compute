# Logging, Troubleshooting and Known Limitations

[Documentation home](README.md)

Record the package version, deployment mode, host OS/kernel, firmware, runtime
version, workload image digest and device PCI IDs before investigating a failure.
Preserve error output; do not disable Secure Boot or discard attestation
baselines to make installation appear successful.

## Kubernetes Diagnostics

```bash
sudo kubectl get nodes -o wide
sudo kubectl get pods -n trusted-compute -o wide
sudo kubectl get pods -n kata-deploy -o wide
sudo kubectl get pods -n kube-system -l app.kubernetes.io/name=nri-plugin-device-injector
sudo kubectl get events -A --sort-by=.metadata.creationTimestamp
sudo kubectl logs -n trusted-compute deployment/attestation-manager --tail=200
sudo kubectl get runtimeclass kata-qemu
```

For a failing pod, substitute its namespace and name:

```bash
sudo kubectl describe pod <pod> -n <namespace>
sudo kubectl logs <pod> -n <namespace> --all-containers --tail=200
sudo kubectl logs <pod> -n <namespace> --all-containers --previous --tail=200
```

`--previous` applies only when a previous container instance exists. Check
initialization-container logs separately when events identify an init failure.

Inspect the service for the installed variant:

```bash
# K3s:
sudo journalctl -u k3s --since "30 minutes ago"
# Existing Kubernetes:
sudo journalctl -u containerd -u kubelet --since "30 minutes ago"
```

## Docker Diagnostics

```bash
sudo docker ps -a
sudo docker logs kata-deploy --tail=200
sudo docker compose -f docker/tw-docker-deploy.yaml ps
sudo docker inspect <container> --format '{{.HostConfig.Runtime}}'
sudo docker logs <container> --tail=200
sudo journalctl -u docker --since "30 minutes ago"
```

Run package-relative Compose commands from the extracted installation directory.
Inspect the container's state as well as its logs: a short-lived device-query
example may have exited successfully rather than failed.

## Common Symptoms

| Symptom | Checks and next action |
| --- | --- |
| Installer rejects Secure Boot | Run `mokutil --sb-state`; fix firmware/boot configuration rather than bypassing the check |
| Installer detects another mode | Remove the previous Trusted Compute mode with its matching uninstaller; do not delete conflict markers by hand |
| Pod remains Pending | Check events, node cordon/taints, requested resources and RuntimeClass; investigate attestation before uncordoning |
| Image pull failure | Check exact image tag/digest, registry access, credentials, proxy configuration and DNS in the selected runtime |
| VM fails to start | Check `/dev/kvm`, runtime logs and matching kernel/image paths; verify the runtime was installed on the workload host |
| Missing Docker Kata shim/config | Check `kata-deploy` logs and host files; normal termination of the installer container removes installed artifacts |
| Docker workload uses the default runtime | Add `--runtime io.containerd.kata.v2` or the Compose `runtime` field and recreate the container |
| Attestation remains false | Inspect manager/Trust Agent/HVS logs and measured-file changes; restore or approve a known-good state through controlled maintenance |
| No GPU/NPU in guest | Check host VFIO binding, IOMMU groups, CDI/device mapping, guest drivers and device readiness |
| CDI annotation has no effect | Check NRI configuration and injector pods; annotation suffix must match the container name |
| HTTP test fails | Check workload readiness, port mapping/Service, firewall, DNS and cluster network policy; isolation does not configure external routing |
| No telemetry | Check guest kernel parameters, collector reachability and accepted protocol/path; no collector is installed by default |

For device diagnosis:

```bash
lspci -nnk
ls -l /dev/vfio
find /sys/kernel/iommu_groups -type l
sudo dmesg | grep -Ei 'vfio|iommu|dmar'
```

Stop workloads before restoring device bindings. Follow the selected
[GPU](trusted_compute_gpu_enablement.md), [NPU](trusted_compute_npu_enablement.md)
or [SR-IOV](sriov_enablement_user_guide.md) guide for cleanup.

## Known Limitations

- The packaged workflows target a standalone Ubuntu 24.04 Intel x86-64 host.
  The existing-Kubernetes installer is not a multi-node fleet deployment tool.
- Docker provides VM isolation but not the Kubernetes host-attestation stack.
- The default QEMU/KVM runtime does not promise protection against a malicious
  host administrator or hardware-encrypted guest memory.
- Attestation compares measured state against enrolled references. Coverage
  depends on the active policy, and a compromised reference invalidates the
  assumption of trust.
- Polling is not per-workload admission. Current failure handling cordons the
  node and attempts pod deletion only in `default`, not all namespaces.
- Linux guest/container execution is supplied. Windows guests and Windows
  containers are not provided by this package.
- GPU/NPU support is hardware-, firmware- and driver-dependent. SR-IOV is not
  available on every integrated GPU; no universal device compatibility is implied.
- CDI names alone do not prevent two pods from requesting the same PCIe function.
- Device examples can expose broad device access for demonstration. Review
  mounts, privileges, network policy and image provenance before production use.
- Installation/removal modifies the host runtime and can disrupt workloads.
  Back up configuration and data; the examples are not a backup/upgrade strategy.

Report reproducible failures through the repository's
[issue tracker](https://github.com/open-edge-platform/trusted-compute/issues).
Redact tokens, credentials and private workload data from diagnostic output.
