// Certificate Management Service (CMS)
//
// CMS resources are used to retrieve root CA certificates and to request CMS Signed Certificates for the provided CSR.
// CMS acts as a root CA and issuing TLS certificates for all other ISecL services.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 3
//  Host: cms.com:8445
//  BasePath: /cms/v1
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token>**
//
// swagger:meta
package cms

// swagger:operation GET /ca-certificates CACertificate GetCACertificates
// ---
// description: |
//   Retrieves the list of root CA Certificates.
//
// produces:
// - application/x-pem-file
// responses:
//   "200":
//     description: Successfully retrieved the list of root CA Certificates.
//     schema:
//       type: string
//       example: |
//         -----BEGIN CERTIFICATE-----
//         MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
//         MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
//         AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
//         VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
//         TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
//         jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
//         rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
//         W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
//         Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
//         5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
//         bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
//         4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
//         g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
//         EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
//         MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
//         ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
//         qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
//         zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
//         i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
//         9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
//         tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
//         jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
//         3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
//         -----END CERTIFICATE-----
//
// x-sample-call-endpoint: https://cms.com:8445/cms/v1/ca-certificates
// x-sample-call-output: |
//         -----BEGIN CERTIFICATE-----
//         MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
//         MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
//         AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
//         VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
//         TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
//         jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
//         rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
//         W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
//         Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
//         5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
//         bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
//         4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
//         g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
//         EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
//         MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
//         ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
//         qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
//         zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
//         i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
//         9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
//         tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
//         jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
//         3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
//         -----END CERTIFICATE-----
// ---

// swagger:operation POST /certificates Certificate GetCmsSignedCertificate
// ---
// description: |
//   Retrieves the certificate signed by CMS. A valid certificate type
//   should be provided as a query parameter for this API Call to distinguish the
//   type of certificate requested. A valid bearer token is required to authorize
//   this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
// - application/x-pem-file
// produces:
// - application/x-pem-file
// parameters:
// - name: request body
//   in: body
//   required: true
//   description: |
//     A valid CSR should be provided as input in PEM format.
//   schema:
//     type: string
//     format: txt
//     example: |
//         -----BEGIN CERTIFICATE REQUEST------
//         MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTV0xTIFRMUyBDZXJ0aWZpY2F0ZTCCASIw
//         DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbH0rV5KhRN/xxhAHM1n9r8185w
//         Gu21zta4koOXNHGDvM6ePRbfpu8erM54b6BGILLjHfM4iLi5s6iRu6uaNhGkSzAt
//         G/J7+K+fR6a1LQ4e7bJbpv7xKz7K7/1ZyIym6c4pxi9i9dib2+CK4H8iNOoYtxCw
//         NT19mpo+yWkwrGRr8SRXwZvBJQKKo6wcOHHTdo6OC5aGbBuP0KU7kEK2zIeGFs0h
//         7gYi2CUWoPjcckTdZKtyIqEC1RsvIsO44OAhc215JNs+ZJmPAZ6oY3WB47Y997Yf
//         Iw3FNTD8pxZRVAd3ngL6R5D3neI/oirryEroemoGF7mQ7uvI/uFVyzUh5dECAwEA
//         AaAAMA0GCSqGSIb3DQEBDAUAA4IBAQCjTLp4TuNVCerqrtNYJywj6G1sbCYKzUL1
//         EwlliEOUCpXpTIqPcaDTpci6Wsh2rUTdMPzPxY9gqJ8b+ZJYTMsyzslZpdvZCXRt
//         0QllF2DS+ETV2DJm7VeikqEjSWrNeQyyFimKo1Eboxr1yZgOClTM2Kq937sE4b/b
//         H9xuI8JIu+H8PlCVoecg3n7Xef5yAGK6eTA1pMSMPafB6DngEXlZLsSdB1QcytCJ
//         Vo9phrmt6CnVciJqul6ukFzoiRizb2OMU1mpstV/TIuEuR/fSqroZXII4U1xPp82
//         1va55WHMBZlmi2T0XC8QKuYMw7FnnWU+whPaBUOgvtFRwoeLKBBR
//         -----END CERTIFICATE REQUEST-------
// - name: certType
//   description: Certificate type such as TLS, Flavor-Signing, JWT-Signing, Signing and TLS-Client.
//   in: query
//   type: string
//   required: true
// responses:
//   "200":
//     description: Successfully retrieved the certificate signed by CMS for provided CSR.
//     schema:
//       type: string
//       example: |
//         -----BEGIN CERTIFICATE------
//         MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTV0xTIFRMUyBDZXJ0aWZpY2F0ZTCCASIw
//         DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbH0rV5KhRN/xxhAHM1n9r8185w
//         Gu21zta4koOXNHGDvM6ePRbfpu8erM54b6BGILLjHfM4iLi5s6iRu6uaNhGkSzAt
//         G/J7+K+fR6a1LQ4e7bJbpv7xKz7K7/1ZyIym6c4pxi9i9dib2+CK4H8iNOoYtxCw
//         NT19mpo+yWkwrGRr8SRXwZvBJQKKo6wcOHHTdo6OC5aGbBuP0KU7kEK2zIeGFs0h
//         7gYi2CUWoPjcckTdZKtyIqEC1RsvIsO44OAhc215JNs+ZJmPAZ6oY3WB47Y997Yf
//         Iw3FNTD8pxZRVAd3ngL6R5D3neI/oirryEroemoGF7mQ7uvI/uFVyzUh5dECAwEA
//         AaAAMA0GCSqGSIb3DQEBDAUAA4IBAQCjTLp4TuNVCerqrtNYJywj6G1sbCYKzUL1
//         EwlliEOUCpXpTIqPcaDTpci6Wsh2rUTdMPzPxY9gqJ8b+ZJYTMsyzslZpdvZCXRt
//         0QllF2DS+ETV2DJm7VeikqEjSWrNeQyyFimKo1Eboxr1yZgOClTM2Kq937sE4b/b
//         H9xuI8JIu+H8PlCVoecg3n7Xef5yAGK6eTA1pMSMPafB6DngEXlZLsSdB1QcytCJ
//         Vo9phrmt6CnVciJqul6ukFzoiRizb2OMU1mpstV/TIuEuR/fSqroZXII4U1xPp82
//         1va55WHMBZlmi2T0XC8QKuYMw7FnnWU+whPaBUOgvtFRwoeLKBBR
//         -----END CERTIFICATE-------
//
// x-sample-call-endpoint: |
//    https://cms.com:8445/cms/v1/certificates?certType=Signing
// x-sample-call-input: |
//         -----BEGIN CERTIFICATE REQUEST------
//         MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTV0xTIFRMUyBDZXJ0aWZpY2F0ZTCCASIw
//         DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbH0rV5KhRN/xxhAHM1n9r8185w
//         Gu21zta4koOXNHGDvM6ePRbfpu8erM54b6BGILLjHfM4iLi5s6iRu6uaNhGkSzAt
//         G/J7+K+fR6a1LQ4e7bJbpv7xKz7K7/1ZyIym6c4pxi9i9dib2+CK4H8iNOoYtxCw
//         NT19mpo+yWkwrGRr8SRXwZvBJQKKo6wcOHHTdo6OC5aGbBuP0KU7kEK2zIeGFs0h
//         7gYi2CUWoPjcckTdZKtyIqEC1RsvIsO44OAhc215JNs+ZJmPAZ6oY3WB47Y997Yf
//         Iw3FNTD8pxZRVAd3ngL6R5D3neI/oirryEroemoGF7mQ7uvI/uFVyzUh5dECAwEA
//         AaAAMA0GCSqGSIb3DQEBDAUAA4IBAQCjTLp4TuNVCerqrtNYJywj6G1sbCYKzUL1
//         EwlliEOUCpXpTIqPcaDTpci6Wsh2rUTdMPzPxY9gqJ8b+ZJYTMsyzslZpdvZCXRt
//         0QllF2DS+ETV2DJm7VeikqEjSWrNeQyyFimKo1Eboxr1yZgOClTM2Kq937sE4b/b
//         H9xuI8JIu+H8PlCVoecg3n7Xef5yAGK6eTA1pMSMPafB6DngEXlZLsSdB1QcytCJ
//         Vo9phrmt6CnVciJqul6ukFzoiRizb2OMU1mpstV/TIuEuR/fSqroZXII4U1xPp82
//         1va55WHMBZlmi2T0XC8QKuYMw7FnnWU+whPaBUOgvtFRwoeLKBBR
//         -----END CERTIFICATE REQUEST-------
// x-sample-call-output: |
//         -----BEGIN CERTIFICATE------
//         MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTV0xTIFRMUyBDZXJ0aWZpY2F0ZTCCASIw
//         DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbH0rV5KhRN/xxhAHM1n9r8185w
//         Gu21zta4koOXNHGDvM6ePRbfpu8erM54b6BGILLjHfM4iLi5s6iRu6uaNhGkSzAt
//         G/J7+K+fR6a1LQ4e7bJbpv7xKz7K7/1ZyIym6c4pxi9i9dib2+CK4H8iNOoYtxCw
//         NT19mpo+yWkwrGRr8SRXwZvBJQKKo6wcOHHTdo6OC5aGbBuP0KU7kEK2zIeGFs0h
//         7gYi2CUWoPjcckTdZKtyIqEC1RsvIsO44OAhc215JNs+ZJmPAZ6oY3WB47Y997Yf
//         Iw3FNTD8pxZRVAd3ngL6R5D3neI/oirryEroemoGF7mQ7uvI/uFVyzUh5dECAwEA
//         AaAAMA0GCSqGSIb3DQEBDAUAA4IBAQCjTLp4TuNVCerqrtNYJywj6G1sbCYKzUL1
//         EwlliEOUCpXpTIqPcaDTpci6Wsh2rUTdMPzPxY9gqJ8b+ZJYTMsyzslZpdvZCXRt
//         0QllF2DS+ETV2DJm7VeikqEjSWrNeQyyFimKo1Eboxr1yZgOClTM2Kq937sE4b/b
//         H9xuI8JIu+H8PlCVoecg3n7Xef5yAGK6eTA1pMSMPafB6DngEXlZLsSdB1QcytCJ
//         Vo9phrmt6CnVciJqul6ukFzoiRizb2OMU1mpstV/TIuEuR/fSqroZXII4U1xPp82
//         1va55WHMBZlmi2T0XC8QKuYMw7FnnWU+whPaBUOgvtFRwoeLKBBR
//         -----END CERTIFICATE-------
// ---
