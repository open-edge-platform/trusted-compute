/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// CaCertificate response payload
// swagger:parameters CaCertificate
type CaCertificate struct {
	// in:body
	Body hvs.CaCertificate
}

// CaCertificateRequest request payload
// swagger:parameters CaCertificate
type CaCertificateRequest struct {
	// in:body
	Body hvs.CaCertificate
}

// CaCertificateCollection response payload
// swagger:parameters CaCertificateCollection
type CaCertificateCollection struct {
	// in:body
	Body hvs.CaCertificateCollection
}

//
// swagger:operation GET /ca-certificates CACertificates SearchCACerts
// ---
// description: |
//   SearchCACerts returns a collection of CA certificates in PEM/JSON format based on domain.
//   Returns - The retrieved CA Certificate collection from the CA Certificates store.
//
// produces:
//   - application/json
//   - application/x-pem-file
// parameters:
//   - name: domain
//     description: Available Certificate Domains are {saml, ek, endorsement, root}
//     in: query
//     type: string
//     required: true
//     enum: [saml, ek, endorsement, root]
//   - name: Accept
//     description: Accept header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
//       - application/x-pem-file
// responses:
//   '200':
//     description: Successfully retrieved the CA Certificate Collection from CertStore.
//     content: application/json
//     schema:
//       $ref: "#/definitions/CaCertificateCollection"
//   '400':
//     description: Invalid domain/Certificate Type provided
//   '415':
//     description: Invalid Accept Header in Request - should be application/json or application/x-pem-file
//   '500':
//     description: Internal server error - Certificates with specified type have not been created/loaded
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/ca-certificates?domain=ek
// x-sample-call-output: |
//   {
//   "ca_certificate": [
//   {
//     "name": "GlobalSign Trusted Platform Module Root CA",
//     "certificate": "MIID/DCCAmSgAwIBAgIBCDANBgkqhkiG9w0BAQwFADBQMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwHhcNMjAwODExMDEzMDE2WhcNMjEwODExMDEzMDE2WjAfMR0wGwYDVQQDExRIVlMgU0FNTCBDZXJ0aWZpY2F0ZTCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALsrGJ2+r+uqHKDC4LyVdyHQB2X9sNvs0eBbUz1bDY/vYAvXaIJ05ay32sxw0MeccvkTWFfS+4us/Ou6cz+9j+vi2MwpMHMWbZb3twj7L6TVagQ4D1kkc6XXBKjnuFLnaRoZPw5CNHT8UgXDI5ZwulMk90MOfbh4Dubp9jGgnFJB0npShZPcIww/spiSUFbhDBCeEe9zRhOHpGtsonRfRRgC8KYMELvS8dgadaJcQt6X079wvNu/YU1ypAf+fa85F+knycsxcN82yu6LwYl6QlFizbrTOqZR/pFL/y8rM4t+xySApOj7sf84uuLGP3YjhCiBS2w2e9AUTav1fwLLja3adJjFtg6p9E7HG5KzUmMt/sd3vU17ZtNQK7OI5BEuKVafuWjIyBYyrp4cEtFZg382x9XWf5L6ZrCBxV0IH7MNkmM56QCwuMU02tZEZhIlz0k+QUu56K/7OO4Fe25SSC4UFPz2AC8v2IF06vLYaas+icfAFoTEnBZzcVZTW63LlwIDAQABoxIwEDAOBgNVHQ8BAf8EBAMCBsAwDQYJKoZIhvcNAQEMBQADggGBAMCsexjl3bqCgmWOcZfMCT+yEf/r6kYUPsMYSzQE4jlxIHVfySNaMUhOsxS6x7XUDizMDGudorH4yLCXGSHfA0uhipArLEeIZjMI0ED6NAnlr3xgUHTQG9bwfCO5Gqw5yh+WrpzuyCjH4I560pf6JSzLuOJcdXf7H3s3f9MNwtTpKl6V2DUj7+X7HvyANyWqALvlSCAxbM2wyt0eIC8DhVkTvsqF5eCqOjkBD4UXj9rPJfFdVdMzhrkzr3iT+XSFHY6WMn6ePcvI6NNkHZ8SCI3A7VSXeiZyIe81igRY3WlkQbRvXEXAuwKC494DrnlN18xMlUBRj70QOW2wgEA1TbZVpGhZzsNBmFFbBttBWb3tBdcxQKbeonKVim2BFealU3uIS3hhxAP7LSNaGUFNC6hZ3hL4iRTR6pYiXgcYlu1LjWt4z/oibCB02Vqjx60xRcN0Pis+4W0acOffnXewTn3468o3UqQzBGOr+tBBL2zNwKDPhiNmkNCmzg/+H4sO7w=="
//   },
//   {
//     "name": "STM TPM EK Root CA",
//     "certificate": "MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UEAxMFQ01TQ0EwHhcNMjAwODExMDEyNzM4WhcNMjUwODExMDEyNzM4WjBQMQswCQYDVQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDCpynt4bdlRofh83Y1xm+6Jk3VGwqQI63PXkUDJ8xqcybMv9S9Au0f165f+DksZ3A+PrtCmyzuL1G4klPgCoY3QeWYEFRrD1qnc1UESD+zyqPizUeKAGHq7x298D8ztrkAT+1ChmdlF2DXB7hIKX69/AjnwyobW/pgJv8V1XG7+nD+wUqyKEzPkQbMrNSoRzf4YjkVWZ4v2DECcHYE3GbUaOZkAo5jaqc74v3D5n33j84aPfsD4aL5VVz/61Akkv6wWlW2NoIecwsjFxr4+oviKy62V9s1Ndti+L9SLaZApEsXjNV7kmtIVllPSb2rO2T1/cTJNGViJrAwMd173JvLLtBL8a1mVZMYXMXmuKc/yIQ0lCwseXQkNrP+jAcZLe0N0U5/hJmwO8ojVaXNg5BfTUefH6kkbIFYB3kpMcCZ99Mvkkm+XQUs3yGHc2bVRdWFgyk3fy5bVzvyY/LpI0FQkIWdCJbcnIZn68mIpiYsJPmM7JxY4Ua1nXitxgGbn9MCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggGBALZqCy21FSA2NI45LT4gOab9K7XrmMB55Jxecnb8QoRAkyBhPgBe5kw2KjXQ1ocoAe/fmiPhAIOPZdgm7H+G5LyYHRIvuqUyAoap9yDH5xvolVz1wBvLU+XLYWN9JfbYWQvDp96FxZ+gvIVKPzMQ1PTXPL6pLU4z6rAE5t94IsKZw7v3ip3KwYnBfEYuzUs+eAD+iLwpXzJcSoCbXWU9aAMv3MElM5EcCrmHvbOML5uS4NG+MBNv9XsLJp3FDs6EkewG/cWgMqGIskXsVbZICTCI7FxnWA0E1k0/qX2tu1QAe74vF2pAT51lKN30w8dn3FLnLyuAEoOfVJF7dOaRS5zwg1J4WD/ubW5WBOi0z1yUa850H7A1zoY9HUYHcrI84pJMaPRVMD4Q6p+JXp/DyEQXYDt6ySRL3dNT4j3rgoGY2P0GosUd4UFJXCFD6EfsfhmDLkweTFV/H+ASSIjs0qUGjRMQCTNvHOB1QoaqE7KvB6BjQFFcnfYj2chSAGbUVA=="
//   }
//   ]
//   }

// swagger:operation POST /ca-certificates CACertificates CreateCACertificate
// ---
// description: |
//   Imports an existing CA certificate into the Certificate store.
//   Returns - The imported CA Certificate from the store.
//
// consumes:
//   - application/json
// produces:
//   - application/json
// x-permissions: cacertificates:create
// security:
//   - bearerAuth: []
// parameters:
//   - name: CreateCACertificate
//     required: true
//     in: body
//     schema:
//       $ref: "#/definitions/CaCertificate"
//   - name: Content-Type
//     description: Content-Type header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
//   - name: Accept
//     description: Accept header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
// responses:
//   '200':
//     description: Successfully created the CA Certificate in CertStore.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/CaCertificate"
//   '400':
//     description: Invalid CACertificate in request body/Invalid type, only root or endorsement ca certificate can be added
//   '415':
//     description: Invalid Accept/Content-Type Header in Request - should be application/json
//   '500':
//     description: Internal server error - Error persisting Certificate in CertStore
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/ca-certificates
// x-sample-call-input: |
//   {
//   "name": "HVS Root Certificate - New",
//   "type": "root",
//   "certificate": "MIIEBjCCAm6gAwIBAgIQN0rzaln9PujeaZe6mfzrezANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDExtIVlMgRW5kb3JzZW1lbnQgQ2VydGlmaWNhdGUwHhcNMjAwODExMDEzMDE5WhcNMjUwODExMDEzMDE5WjAmMSQwIgYDVQQDExtIVlMgRW5kb3JzZW1lbnQgQ2VydGlmaWNhdGUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDFW0RgQdEL7j43LBaCkHyPE8gbk/Ig49Ba/7YaU0DLDg2cGEl8HmNrMA50TJt3uq7HOpFxXt9n9Yy/SyiK0GBSon+ix4x23WEFRaVsDBNJOkM7jvsVIIRN18nySK5IMNvGuLAWwrE7IredC5sTsHClUN6ExQycg6clrEb9UvDqQO2u7GebnRAjXWuSMW/ZuhNkMBh+HSLKB5+GL4KAl96yyusfvXLgUiEJAxv5vh9A1f2JStZWtlqfzPBYabIe6W9JPhLYGrE2gD1TEklqQMJ6YNpVfNJTwWiKB/sT5F+3wnlNp+7J1O0W1FkboZSjDf7smDfV30ma1pWL2K6vJjG65Rh6/eGdIbPRp6JKfVM99IoNUSTzCj39qFrVxpPK1+5yG0JwUJKEKRJKte/UTLnTU++l/ShzVjsmuLhm22V6mSjoZgrqdq/EqZy641J/k/+Dmd14aKzIJxgUrHJhosfAwzhGNGk5AsXgaMk9J0R7QGYB4qptj4sx4IURFC6X2JkCAwEAAaMwMC4wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0RBAQwAoIAMA0GCSqGSIb3DQEBCwUAA4IBgQBU42dQ/WxJSa+v5+TIsRWOHbvZUV5k8JJFXdlPfu6sPAYAy/rvqWhfAUyhHYGlYdRW5qXDm/jtHUjSUqMPl9T48bxjCYl3wVVRrhk/zX/YFhjV/fDHSqgRGGTfvH/zb7oJMPG+vRmh8hH6OLk6NMnvD1K025S0YyQEoYOxbNnPkU6o2t5hyvKwRFDzTUHO2waPejZ40zSy/MRDSl3R3wIdoWASXdYugbdBqkFc9YVQXs7FIt9RmJKIWZe2chx61bZqw6mBSQpdj0oh6o4pqL1QrQbpnWsYEPvPZFM3lqj/h/QgvX79n5CfSmhoaUosSwnAhpciu4cB/xPOO/9ezdOhpSv4y9jjQ+eUaq8JD/K2a+U815QpsenSZar4cUjW8WqlbZ3ykzFPEPpc4KjyVok5j4Wc53f3HwWyeDC2sTMAZ7JJ51HL6yE3nOfnuhb41iVAhzgGNUegL+C0E+/ZyKjJl/SJbovCRjYtDyHL1TZDrCvmxQjci6XA+tw4tSL9o5o="
//   }
// x-sample-call-output: |
//   {
//   "name": "HVS Root Certificate - New",
//   "type": "root",
//   "certificate": "MIIEBjCCAm6gAwIBAgIQN0rzaln9PujeaZe6mfzrezANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDExtIVlMgRW5kb3JzZW1lbnQgQ2VydGlmaWNhdGUwHhcNMjAwODExMDEzMDE5WhcNMjUwODExMDEzMDE5WjAmMSQwIgYDVQQDExtIVlMgRW5kb3JzZW1lbnQgQ2VydGlmaWNhdGUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDFW0RgQdEL7j43LBaCkHyPE8gbk/Ig49Ba/7YaU0DLDg2cGEl8HmNrMA50TJt3uq7HOpFxXt9n9Yy/SyiK0GBSon+ix4x23WEFRaVsDBNJOkM7jvsVIIRN18nySK5IMNvGuLAWwrE7IredC5sTsHClUN6ExQycg6clrEb9UvDqQO2u7GebnRAjXWuSMW/ZuhNkMBh+HSLKB5+GL4KAl96yyusfvXLgUiEJAxv5vh9A1f2JStZWtlqfzPBYabIe6W9JPhLYGrE2gD1TEklqQMJ6YNpVfNJTwWiKB/sT5F+3wnlNp+7J1O0W1FkboZSjDf7smDfV30ma1pWL2K6vJjG65Rh6/eGdIbPRp6JKfVM99IoNUSTzCj39qFrVxpPK1+5yG0JwUJKEKRJKte/UTLnTU++l/ShzVjsmuLhm22V6mSjoZgrqdq/EqZy641J/k/+Dmd14aKzIJxgUrHJhosfAwzhGNGk5AsXgaMk9J0R7QGYB4qptj4sx4IURFC6X2JkCAwEAAaMwMC4wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0RBAQwAoIAMA0GCSqGSIb3DQEBCwUAA4IBgQBU42dQ/WxJSa+v5+TIsRWOHbvZUV5k8JJFXdlPfu6sPAYAy/rvqWhfAUyhHYGlYdRW5qXDm/jtHUjSUqMPl9T48bxjCYl3wVVRrhk/zX/YFhjV/fDHSqgRGGTfvH/zb7oJMPG+vRmh8hH6OLk6NMnvD1K025S0YyQEoYOxbNnPkU6o2t5hyvKwRFDzTUHO2waPejZ40zSy/MRDSl3R3wIdoWASXdYugbdBqkFc9YVQXs7FIt9RmJKIWZe2chx61bZqw6mBSQpdj0oh6o4pqL1QrQbpnWsYEPvPZFM3lqj/h/QgvX79n5CfSmhoaUosSwnAhpciu4cB/xPOO/9ezdOhpSv4y9jjQ+eUaq8JD/K2a+U815QpsenSZar4cUjW8WqlbZ3ykzFPEPpc4KjyVok5j4Wc53f3HwWyeDC2sTMAZ7JJ51HL6yE3nOfnuhb41iVAhzgGNUegL+C0E+/ZyKjJl/SJbovCRjYtDyHL1TZDrCvmxQjci6XA+tw4tSL9o5o="
//   }
//

// swagger:operation GET /ca-certificates/{certType} CACertificates RetrieveCACertificate
// ---
// description: |
//   Retrieve returns an existing CA certificate from the Certificate store.
//   Returns - The retrieved CA Certificate from the Certificate store.
//
// produces:
//   - application/json
// parameters:
//   - name: certType
//     description: Available Certificate Types are {root, endorsement, ek, privacy, aik, tag, saml, tls}
//     in: path
//     type: string
//     required: true
//     enum:
//       - root
//       - endorsement
//       - ek
//       - privacy
//       - aik
//       - tag
//       - saml
//       - tls
//   - name: Accept
//     description: Accept header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
// responses:
//   "200":
//     description: Successfully retrieved the CA Certificate from CertStore.
//     content: application/json
//     schema:
//       $ref: "#/definitions/CaCertificate"
//   "400":
//     description: Invalid Certificate Type provided
//   "415":
//     description: Invalid Accept Header in Request - should be application/json
//   "500":
//     description: Internal server error - Certificates with specified type have not been created/loaded
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/ca-certificates/tag
// x-sample-call-output: |
//   {
//     "name": "HVS Tag Certificate",
//     "certificate": "MIID9zCCAl+gAwIBAgIRANtyyihLjg1Jeh6j1bxsApEwDQYJKoZIhvcNAQELBQAwHjEcMBoGA1UEAxMTSFZTIFRhZyBDZXJ0aWZpY2F0ZTAeFw0yMDA4MTEwMTMwMjFaFw0yNTA4MTEwMTMwMjFaMB4xHDAaBgNVBAMTE0hWUyBUYWcgQ2VydGlmaWNhdGUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC7WJP2DKkRPBmjd0Rkxf1QcMN3vcTTTXNjJGOe+DXgLcveH8XSQOqhP/fkUn5+1dbdlrlPT48i2381opczX0B2pfZ1W3vlw6XzX2Y7+hW71/5k95hUrNcpUjlkfg+hN9RqnwtkVQIDOK9OhxuRiifycX/3rhymoeVxV9v/8L2evEyD37TENTNBL6yH6vk0qBIK6tqJlXg3k8xIv4J4jHd0ftQ6N5XC+6vXIEN1DCWc8t2ZHkRpMCVxQbzYWLjf31c+/H90HPbiQKjDLR8epCsck38Qm6Ge9/89TztWeCTCu1xI1evTOUpgH8OprsCTqS71wnFxBRP7uVuQCTeGII1/NfOs0Tj+tGXiUsJDDSKSDAE8CEdoqLHXVoCTcQKW3rAga8AARYh7cLHGhus3BqG4ABIzZxONuAEkElJM8BeC8k9av6S4lSNlwpFPXO+w9+h5rNqUMC0R9+kWT08WganMaX18PeJ6WW/vg4SJ+tc0vZTCAHadx6tcH7asoAKWchMCAwEAAaMwMC4wDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0RBAQwAoIAMA0GCSqGSIb3DQEBCwUAA4IBgQAljHqgnNyHWXsKxW3bB6Es3Bnsqud71esHULdKj55ygi94U2Tte+Wp5os596KhBDMpiopCTepAmSzPZ2l9A73lFlbHvYmfek6RS0G7NAjltMCmQnRm3t6PaDK1vE1Q4XrM76q52KXYgCMrpza5kWql+ZNDfp08XMYm0j6t/XYHp2XP3iuHVMtJ+Uf8yRqUlK89pE7c9JuJqcJ9w121WjHrzSj9CKK8glSqHtVyzOgekWMHnRz82HDvTihfXfgkDbz1oG2cR6XT8u8h6x5NJIBPVw7GrgYVFVV7vabfocKHFR5mnLmkDiKBFUSoSCVE7eooaj/oAo9V+tW1dzdUvLAbyoswHre71JmDtyTIfterp16qkcdtkUDgNCayXnM32xDgqkMXKKEkryItUFNUmIqv40IiiKvyozrO0+oXOBNf/hJL9g/O4ziV2uC/BqRq5CgxutW+08DRPvV60VwVUcRNnyMmADBRpQu7Qd5HXN566Cufl4rQboObq9xTN+Xftck="
//   }
//
