// Authentication and Authorization Service (AAS)
//
// The Authentication and Authorization Service (AAS) is a component responsible for generating and maintaining
// user authentication and authorization information and issue the users with a JWT for accessing various ISECL services.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 3
//  Host: aas.com:8444
//  BasePath: /aas/v1
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package aas

// swagger:operation GET /jwt-certificates JwtCertificate getJwtCertificate
// ---
// description: |
//   Retrieves the list of jwt certificates.
//
// produces:
// - application/x-pem-file
// responses:
//   "200":
//     description: Successfully retrieved the list of jwt certificates.
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
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/jwt-certificates
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
