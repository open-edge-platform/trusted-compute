# Foundational Security Attestation APIs

[Documentation home](README.md) | [Kubernetes deployment](kubernetes.md)

Trusted Compute uses TPM-backed host measurements and reference measurements
called **flavors** to evaluate host trust. These APIs apply to the attestation
services installed by the **Kubernetes** workflow (K3s or existing Kubernetes).
The Docker/container-based workflow does not install these services.

## Core Services

| Service | Purpose | Reference |
| --- | --- | --- |
| Authentication and Authorization Service (AAS) | Issues JWTs and manages users, roles and permissions for service API access | [AAS API](aas-api.md) |
| Certificate Management Service (CMS) | Provides the CA hierarchy and signs service TLS and signing certificates | [CMS API](cms-api.md) |
| Host Verification Service (HVS) | Manages flavors and hosts, verifies TPM-backed evidence and produces trust reports | [HVS API](hvs-api.md) |
| Trust Agent (TA) | Collects host measurements and supplies TPM quotes to HVS | [Attestation flow](capabilities.md#attestation-and-security-flows) |

## Typical Attestation Flow

1. **Bootstrap trust:** CMS provides certificates used to establish trusted TLS
   connections and verify signatures. Certificate provisioning and API
   authorization are separate concerns.
2. **Authenticate:** a service or administrator submits credentials to AAS
   `POST /aas/v1/token`. Protected API calls use the returned JWT in
   `Authorization: Bearer <token>` and require the appropriate roles/permissions.
3. **Define expected state:** HVS stores flavors and flavor groups describing
   acceptable platform and OS measurements. Create references only from a
   known-good host.
4. **Register the host:** HVS associates the host's Trust Agent connection with
   the applicable flavor groups.
5. **Collect evidence:** HVS requests a TPM quote and measurement evidence from
   the Trust Agent. The TPM signs the quote using its attestation identity key.
6. **Verify:** HVS compares the evidence with the applicable flavors and produces
   a trust report. Report endpoints support JSON and, for selected operations,
   SAML.

The packaged Attestation Manager automates host registration, reference creation
and report polling. These API examples are an administrative reference, not
additional mandatory installation steps. Do not recreate or delete manager-owned
hosts or flavors merely to obtain a passing report. See
[reference measurements and recovery](capabilities.md#reference-measurements-and-recovery)
and the documented [enforcement limitations](capabilities.md#attestation-and-security-flows).
