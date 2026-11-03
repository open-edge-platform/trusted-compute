# Common Trusted Compute Capabilities

[Documentation home](README.md)

This guide documents shared concepts once. The
[deployment options guide](deployment-options.md)
identifies which capabilities each installer actually enables.

## Trusted VM Lifecycle

1. The operator installs a matching Kata runtime, guest kernel and Trusted VM
   image using `kata-deploy`.
2. The application explicitly selects the Kata runtime. The host runtime pulls
   its container image and prepares the container filesystem.
3. The Kata shim starts QEMU/KVM and boots the guest. A Kubernetes pod is a
   sandbox boundary; its containers share the VM.
4. The shim communicates over vsock with the Kata agent. The agent prepares the
   container environment and starts the workload inside the guest.
5. Logs and lifecycle requests are exposed through Kubernetes or Docker.
6. Removing the pod/container tears down its sandbox as appropriate. Persistent
   application data must be managed separately from the ephemeral guest.

Use Kubernetes or Docker to manage workloads rather than manually killing QEMU.
Stop all consumers before unbinding a PCIe device or removing the Kata runtime.

## Trusted VM Configuration

The package supplies a Linux guest built from Edge Microvisor Toolkit artifacts
and a Kata agent. The host kernel and guest kernel are distinct: a host driver
installation alone does not add that driver to the guest.

Common workload overrides include:

| Annotation suffix under `io.katacontainers.config.hypervisor.` | Purpose |
| --- | --- |
| `default_memory` | Initial/default VM memory in MiB |
| `pcie_root_port` | PCIe root ports for device attachment |
| `hot_plug_vfio` | VFIO attachment topology, such as `root-port` |
| `kernel_params` | Additional guest kernel parameters, when permitted by the installed annotation policy |

Annotations must be enabled by the installed Kata configuration. Kubernetes puts
them on the pod; Docker Compose puts them under the application service's
`annotations`. Container limits and VM memory settings are separate controls.

Keep kernel, image, agent and runtime versions aligned. Global configuration
edits affect subsequent VM launches and can change measured host files. Back up
configuration, use a maintenance window, and validate both workload startup and,
on Kubernetes, attestation after changes.

## Workload Integrity Verification

Distinguish three different checks:

1. **Image identity:** use an approved registry and pin the workload image by
   digest. Container image content-addressing checks transferred content against
   that digest; it does not establish publisher identity or trust.
2. **Host/runtime integrity:** on Kubernetes, the Trust Agent and verifier compare
   measured platform/OS/runtime state against reference flavors. IMA coverage
   depends on the configured policy and allowlist; it is not a blanket hash
   check of every application file.
3. **Execution isolation:** selecting the Kata runtime places the application in
   a guest VM rather than sharing the host kernel.

The supplied launch examples do not configure image-signature admission,
guest-side verification of every workload file, or attestation-based secret
release. Add and validate those controls separately if your threat model needs
them. A successful container launch or a trusted host report is not proof of
application correctness.

The packaged Trust Agent policy measures accesses by the `tc-ima` user
(UID 504) into PCR 11. Its allowlist includes Kata runtime binaries, QEMU
configuration, the guest kernel and `trusted-vm.img`, alongside verifier
artifacts. Consult the release's
[Trust Agent values](https://github.com/open-edge-platform/trusted-compute/blob/main/helm/attestation-verifier/charts/trustagent/values.yaml)
for exact paths and policy; do not assume all container root filesystems are
covered by that allowlist.

## Attestation and Security Flows

This section applies to the packaged **Kubernetes** installation.

For service endpoints, authentication and request examples, see the
[attestation API overview](attestation-api.md) and its AAS, CMS and HVS references.

1. Secure Boot and measured boot establish the host boot evidence. IMA records
   runtime measurements according to its policy.
2. The Trust Agent provides host metadata, event logs and TPM-backed quotes
   to HVS. AAS and CMS support service authentication and certificates.
3. The Attestation Manager registers the host and creates reference flavors
   when its flavor-update marker is absent. A flavor is a set of acceptable
   measurements used for comparison, not a security certification.
4. The manager periodically requests a trust report and checks overall trust
   and Secure Boot status. Reports include platform/OS/IMA trust information.
5. On failed trust or disabled Secure Boot, it attempts to cordon the Kubernetes
   node and then remove pods on that node in the `default` namespace.

**Enforcement limitation:** the current drain implementation is not a full
all-namespace eviction policy. Workloads outside `default`, already-running
workloads and workloads that bypass normal scheduling need separate operational
controls. Cordon alone prevents ordinary new scheduling; it does not terminate
every existing VM.

The package sets polling to **5 minutes**; the base Helm chart defaults to
**60 minutes**. This is a polling loop, not instantaneous per-launch admission.
Inspect manager logs to confirm successful reports, not just that the pod is
Running.

### Reference Measurements and Recovery

Enroll only a known-good host. Reference creation is controlled by the manager's
marker file (`/mnt/attestation_mgr/flavor_update` inside the container); it must
not be described as unconditional re-enrollment on every reboot. Preserve
verifier data and understand baseline changes during reinstall or maintenance.

On failure, preserve reports/logs, determine whether the change was authorized,
and remediate the host before restoring service. Do not delete flavors or marker
files merely to obtain a passing result. Confirm a successful trust report and
review node scheduling state before explicitly uncordoning the node. The manager
does not provide a documented automatic recovery workflow for every failure.

Docker's installer does not deploy any of this attestation/reporting/enforcement
flow; its Secure Boot precheck is not a substitute.

## PCIe Device Passthrough

VFIO assigns a physical PCIe function, or an SR-IOV virtual function, to a VM.
Prepare IOMMU isolation on the host, bind the intended function to `vfio-pci`,
and ensure the guest has compatible drivers and firmware.

- Treat an IOMMU group as an isolation unit; inspect all devices in the group.
- Do not detach host boot/storage/network devices needed to operate the node.
- Whole-iGPU binding removes the GPU from host use and can stop the display
  manager. Maintain an SSH/console recovery path.
- Only one VM should own a given function at a time. CDI injection is not a
  scheduler resource reservation or a device-sharing mechanism.
- With SR-IOV, separate VFs can serve separate VMs if hardware and drivers
  support it. Do not combine whole-PF passthrough with a VF-based workflow.

Kubernetes examples inject CDI devices through the NRI device injector. Docker
examples pass VFIO group devices directly. They share host preparation but not
the application configuration syntax.

## GPU and NPU Enablement

| Device path | Host preparation and model-specific examples |
| --- | --- |
| Whole Intel iGPU | [GPU enablement](trusted_compute_gpu_enablement.md) |
| Intel NPU and companion Signal Processing Controller | [NPU enablement](trusted_compute_npu_enablement.md) |
| Intel iGPU SR-IOV VFs | [SR-IOV enablement](sriov_enablement_user_guide.md) |

The GPU/NPU guides also describe optional guest telemetry. A collector is not
installed by Trusted Compute; configure a reachable, appropriately protected
endpoint and verify data delivery. Telemetry is not attestation evidence.

For operational diagnostics and unsupported assumptions, see
[logging, troubleshooting and known limitations](troubleshooting.md).
