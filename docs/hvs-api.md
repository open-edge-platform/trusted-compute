# HVS API Reference

[Documentation home](README.md) | [Attestation API overview](attestation-api.md)

The Host Verification Service (HVS) manages reference flavors, registers hosts,
requests TPM-backed evidence from Trust Agents and produces trust reports.

**Base URL:** `https://<hvs-host>:<port>/hvs/v2`

Use the [connection and TLS settings](attestation-api.md#service-urls-and-tls)
and an [AAS token](aas-api.md#request-a-token). Except for `/version`, every
endpoint listed here requires `Authorization: Bearer <token>` with the indicated
HVS permission. JSON requests use `Content-Type: application/json`.

These are administrative operations, not extra installation steps. The
Attestation Manager manages the packaged host's registration and references.
Changing or deleting them can affect attestation and scheduling.

## Version

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Get service version | GET | `/version` | None | None |

```bash
curl --fail --show-error --cacert "$CA_CERT" "$HVS_URL/version"
```

## Flavor Templates

Flavor templates define rules used to generate flavors from host measurements.
Conditions select applicable host manifests.

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search templates | GET | `/flavor-templates` | `flavor-template:search` | Query: `id`, `label`, `conditionContains`, `flavorPartContains`, `includeDeleted` |
| Create a template | POST | `/flavor-templates` | `flavor-template:create` | JSON: `flavor_template` containing `label`, `condition[]`, `flavor_parts` |
| Retrieve a template | GET | `/flavor-templates/{flavortemplate_id}` | `flavor-template:retrieve` | Path: `flavortemplate_id` |
| Soft-delete a template | DELETE | `/flavor-templates/{flavortemplate_id}` | `flavor-template:delete` | Path: `flavortemplate_id` |

Prepare `flavor-template.json` with rules appropriate for your host, following
the [template model](../attestation-verifier/src/pkg/model/hvs/flavortemplate.go).
Do not treat an empty rule set as a validated baseline.

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$HVS_URL/flavor-templates" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @flavor-template.json
```

## Flavor Groups

A flavor group associates flavors with match policies such as `ANY_OF`,
`ALL_OF` or `LATEST`, and requirements such as `REQUIRED` or
`REQUIRED_IF_DEFINED`. Default groups include `automatic`, `host_unique` and
`platform_software`.

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search groups | GET | `/flavorgroups` | `flavorgroups:search` | Query: `id`, `nameEqualTo`, `nameContains`, `includeFlavorContent` |
| Create a group | POST | `/flavorgroups` | `flavorgroups:create` | JSON: `name`, `flavor_match_policy_collection.flavor_match_policies[]` |
| Retrieve a group | GET | `/flavorgroups/{flavorgroup_id}` | `flavorgroups:retrieve` | Path: `flavorgroup_id` |
| Delete a group | DELETE | `/flavorgroups/{flavorgroup_id}` | `flavorgroups:delete` | Path: `flavorgroup_id` |

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/flavorgroups?nameEqualTo=automatic" \
  -H "Authorization: Bearer $TOKEN"
```

For creation, use the
[flavor group model](../attestation-verifier/src/pkg/model/hvs/flavor_group.go)
to define the policy; a group's name alone does not establish a trusted baseline.

## Flavors

A flavor contains reference measurements and metadata for a flavor part, such
as `PLATFORM`, `OS`, `ASSET_TAG`, `HOST_UNIQUE`, `IMA` or `SOFTWARE`.

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Create a software flavor | POST | `/flavor-from-app-manifest` | `software_flavors:create` | XML `ManifestRequest` with `Manifest` and applicable `hostId`/`connectionString`, `flavorgroupNames` |
| Search flavors | GET | `/flavors` | `flavors:search` | Query: `id`, `key`, `value`, `flavorgroupId`, `flavorParts` |
| Create flavors | POST | `/flavors` | See below | JSON: `connection_string`, or `flavor_collection`/`signed_flavor_collection`; optional `flavorgroup_names`, `partial_flavor_types` |
| Retrieve a signed flavor | GET | `/flavors/{flavor_id}` | `flavors:retrieve` | Path: `flavor_id` |
| Delete a flavor | DELETE | `/flavors/{flavor_id}` | `flavors:delete` | Path: `flavor_id` |

The create-flavors route accepts `flavors:create`, `software_flavors:create`,
`host_unique_flavors:create` or `tag_flavors:create`; the requested flavor parts
are subject to permission checks. Use the
[flavor request model](../attestation-verifier/src/pkg/model/hvs/flavor.go)
for the nested collection shapes.

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/flavors" \
  -H "Authorization: Bearer $TOKEN"
```

To create a software flavor, prepare a valid `manifest-request.xml` using the
[application manifest API definition](../attestation-verifier/src/docs/shared/hvs/flavor-from-app-manifest.go):

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$HVS_URL/flavor-from-app-manifest" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/xml' \
  --data-binary @manifest-request.xml
```

## Host Status

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search status records | GET | `/host-status` | `host_status:search` | Query: `id`, `hostName`, `hostId`, `hostHardwareId`, `hostStatus`, `fromDate`, `toDate`, `numberOfDays`, `latestPerHost` |
| Retrieve a status and host manifest | GET | `/host-status/{hoststatus_id}` | `host_status:retrieve` | Path: `hoststatus_id` |

Host states include `CONNECTED`, `QUEUE`, `CONNECTION_FAILURE`, `UNAUTHORIZED`,
`AIK_NOT_PROVISIONED`, `EC_NOT_PRESENT`, `MEASURED_LAUNCH_FAILURE`,
`TPM_OWNERSHIP_FAILURE`, `TPM_NOT_PRESENT`, `UNSUPPORTED_TPM` and `UNKNOWN`.
`CONNECTED` describes connectivity, not a passing trust report.

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/host-status?latestPerHost=true" \
  -H "Authorization: Bearer $TOKEN"
```

## Hosts

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search hosts | GET | `/hosts` | `hosts:search` | Query: `id`, `nameEqualTo`, `nameContains`, `hostHardwareId`, `key`, `value`, `trusted`, `getTrustStatus`, `getHostStatus` |
| Register a host | POST | `/hosts` | `hosts:create` | JSON: `host_name`, `connection_string`; optional `flavorgroup_names`, `description` |
| Retrieve a host | GET | `/hosts/{host_id}` | `hosts:retrieve` | Path: `host_id`; query: `getReport`, `getHostStatus` |
| Update a host | PUT | `/hosts/{host_id}` | `hosts:store` | Path: `host_id`; JSON host fields such as `host_name`, `connection_string`, `flavorgroup_names`, `description` |
| Delete a host | DELETE | `/hosts/{host_id}` | `hosts:delete` | Path: `host_id` |

Search before registering a host to avoid duplicating manager-owned records:

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/hosts?getTrustStatus=true&getHostStatus=true" \
  -H "Authorization: Bearer $TOKEN"
```

For manual registration, prepare `host.json` using the
[host model](../attestation-verifier/src/pkg/model/hvs/host.go), with a Trust
Agent connection reachable from HVS and valid flavor group names:

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$HVS_URL/hosts" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @host.json
```

## Reports

A trust report includes the overall trust result, per-part results, rule
evaluations and faults. Check its expiration and host identity as well as the
trust result. Report validity and refresh behavior depend on service
configuration; an old passing report does not establish current host trust.

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search reports | GET | `/reports` | `reports:search` | Query: `id`, `hostId`, `hostName`, `hostHardwareId`, `hostStatus`, `fromDate`, `toDate`, `numberOfDays`, `latestPerHost` |
| Create a report | POST | `/reports` | `reports:create` | JSON host selector: `host_id`, `host_name` or `hardware_uuid`; optional query: `process=async` |
| Retrieve a report | GET | `/reports/{report_id}` | `reports:retrieve` | Path: `report_id` |

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/reports?numberOfDays=2&latestPerHost=true" \
  -H "Authorization: Bearer $TOKEN"
```

To request a report, replace the example hostname with a registered host:

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$HVS_URL/reports" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host_name":"host-1"}'
```

The default response format is JSON. Collection GET and POST also support
`Accept: application/samlassertion+xml`. For asynchronous JSON creation,
`process=async` queues the host and returns without a completed report; search
reports later rather than interpreting request acceptance as a trust verdict.

## TPM Endorsements

A TPM endorsement certificate identifies a TPM endorsement key. Endorsement
records are separate from host trust reports.

| Operation | Method | Path | Permission | Input |
| --- | --- | --- | --- | --- |
| Search endorsements | GET | `/tpm-endorsements` | `tpm_endorsements:search` | Query: `id`, `hardwareUuidEqualTo`, `issuerEqualTo`, `issuerContains`, `revokedEqualTo`, `commentEqualTo`, `commentContains` |
| Register an endorsement | POST | `/tpm-endorsements` | `tpm_endorsements:create` | JSON: `hardware_uuid`, `issuer`, `certificate`; optional `revoked`, `comment` |
| Retrieve an endorsement | GET | `/tpm-endorsements/{tpm-endorsement_id}` | `tpm_endorsements:retrieve` | Path: `tpm-endorsement_id` |
| Update an endorsement | PUT | `/tpm-endorsements/{tpm-endorsement_id}` | `tpm_endorsements:store` | Path: `tpm-endorsement_id`; JSON endorsement fields: `certificate`, `hardware_uuid`, `issuer`, `revoked`, `comment` |
| Delete an endorsement | DELETE | `/tpm-endorsements/{tpm-endorsement_id}` | `tpm_endorsements:delete` | Path: `tpm-endorsement_id` |

The `certificate` field contains a base64-encoded PEM certificate. Use
`hardware_uuid`, not `hardwareUuid`, in JSON bodies. Prepare a valid endorsement
payload for updates rather than assuming a partial revocation-only body is
accepted. See the
[endorsement model](../attestation-verifier/src/pkg/model/hvs/tpm_endorsements.go).

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  "$HVS_URL/tpm-endorsements" \
  -H "Authorization: Bearer $TOKEN"
```

For detailed response schemas and additional operations, see the
[HVS API definitions](../attestation-verifier/src/docs/shared/hvs) and
[implemented routes](../attestation-verifier/src/pkg/hvs/router).
