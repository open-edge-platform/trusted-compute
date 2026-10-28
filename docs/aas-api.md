# AAS API Reference

[Documentation home](README.md) | [Attestation API overview](attestation-api.md)

The Authentication and Authorization Service (AAS) issues JWT bearer tokens and
manages service users, roles and permissions.

**Base URL:** `https://<aas-host>:<port>/aas/v1`

Use the [connection and TLS settings](attestation-api.md#service-urls-and-tls).
Protected endpoints require `Authorization: Bearer <token>` and the permission
listed below. "None" means no bearer token is required; `/token` still validates
the supplied username and password.

## Endpoints

| Operation | Method | Path | Authorization | Input |
| --- | --- | --- | --- | --- |
| Get service version | GET | `/version` | None | None |
| Issue a user JWT | POST | `/token` | None | JSON: `username`, `password` |
| Issue a custom-claims JWT | POST | `/custom-claims-token` | Bearer; `custom_claims:create` | JSON: `subject`, `validity_seconds`, `claims.roles[]` |
| Issue NATS credentials | POST | `/credentials` | Bearer; `credential:create` | JSON: `type` (`HVS` or `TA`), `parameters` including `host-id` for TA |

## Request a Token

Prepare a locally protected `credentials.json` containing the `username` and
`password` for your provisioned AAS account. Do not use example passwords or
commit this file. The response is a JWT string, not a JSON token object:

```bash
TOKEN=$(curl --fail --silent --show-error --cacert "$CA_CERT" \
  -X POST "$AAS_URL/token" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/jwt' \
  --data-binary @credentials.json)
```

Continue only if the request succeeds. An expired token must be replaced with a
new token; a valid token does not grant permissions absent from its account.

## Version, Custom Claims and Credentials

Retrieve the service version:

```bash
curl --fail --show-error --cacert "$CA_CERT" "$AAS_URL/version"
```

Prepare `custom-claims.json` with the subject, validity and roles authorized for
the intended service, then request the token:

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$AAS_URL/custom-claims-token" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/jwt' \
  --data-binary @custom-claims.json
```

For TA NATS credentials, prepare `nats-credentials.json` with this shape,
replacing the hostname with the Trust Agent's FQDN:

```json
{
  "type": "TA",
  "parameters": {
    "host-id": "trustagent.example.com"
  }
}
```

The response contains sensitive NATS authentication material, including an NKEY
seed. Save it only to a protected location:

```bash
(umask 077; curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$AAS_URL/credentials" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'Accept: text/plain' \
  --data-binary @nats-credentials.json \
  --output nats.creds)
```

NATS credentials are for the messaging transport, not a replacement for the
bearer token used by REST APIs.

See the [AAS API definitions](../attestation-verifier/src/docs/shared/aas) for
user/role operations and detailed response definitions.
