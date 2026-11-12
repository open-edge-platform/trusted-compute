# CMS API Reference

[Documentation home](README.md) | [Attestation API overview](attestation-api.md)

The Certificate Management Service (CMS) provides the root/intermediate CA
certificates and signs TLS and signing certificates for attestation services.

**Base URL:** `https://<cms-host>:<port>/cms/v1`

Use the [connection and TLS settings](attestation-api.md#service-urls-and-tls).

## Endpoints

| Operation | Method | Path | Authorization | Input |
| --- | --- | --- | --- | --- |
| Get service version | GET | `/version` | None | None |
| Retrieve CA certificates | GET | `/ca-certificates` | None | None |
| Sign a certificate request | POST | `/certificates` | Bearer; CMS `CertApprover` role with suitable context | Required query: `certType`; body: PEM-encoded CSR |

Certificate types include `TLS`, `TLS-Client`, `Signing`, `JWT-Signing` and
`Flavor-Signing`. The requested type and CSR must satisfy the approver role's
context and certificate validation rules. Signing requests require both
`Content-Type: application/x-pem-file` and `Accept: application/x-pem-file`.

## Examples

Retrieve the service version and CA certificates using an already trusted CA
bundle:

```bash
curl --fail --show-error --cacert "$CA_CERT" "$CMS_URL/version"

curl --fail --show-error --cacert "$CA_CERT" \
  "$CMS_URL/ca-certificates" \
  -H 'Accept: application/x-pem-file'
```

Prepare `request.csr` for the intended signing identity and obtain an
appropriately authorized [AAS token](aas-api.md#request-a-token). Submit only
the CSR, never its private key:

```bash
curl --fail --show-error --cacert "$CA_CERT" \
  -X POST "$CMS_URL/certificates?certType=Signing" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/x-pem-file' \
  -H 'Accept: application/x-pem-file' \
  --data-binary @request.csr \
  --output signed-certificate.pem
```

The successful signing response is a PEM certificate. A rejected request must
be corrected rather than bypassing TLS verification or expanding the account's
privileges indiscriminately.

See the [CMS routes](../attestation-verifier/src/pkg/cms/router) and
[CSR validation](../attestation-verifier/src/pkg/cms/validation/validate_csr.go)
for the implemented certificate handling rules.
