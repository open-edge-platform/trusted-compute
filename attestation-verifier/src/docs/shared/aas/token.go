/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

// UserCredInfo request payload
// swagger:parameters UserCredInfo
type UserCred struct {
	// in:body
	Body aas.UserCred
}

// CustomClaimsInfo request payload
// swagger:parameters CustomClaimsInfo
type CustomClaims struct {
	// in:body
	Body aas.CustomClaims
}

// swagger:operation POST /token Token getJwtToken
// ---
// description: |
//   Creates a new bearer token that can be used in the Authorization header for other API
//   requests. Bearer token Authorization is not required when requesting token for Authservice
//   registered users.
//
// consumes:
// - application/json
// produces:
// - application/jwt
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/UserCred"
// responses:
//   '200':
//     description: Successfully created the bearer token.
//     schema:
//       type: string
//       example: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImYwY2UyNzhhMGM0OGI5NjE3YzQxNzViYmMz
//         ZWIyNThjNDEwYzI2NzUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZ
//         SI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsI
//         m5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc
//         2VyUm9sZU1hbmFnZXIifV0sImV4cCI6MTU3OTE4ODEwMSwiaWF0IjoxNTc5MTgwO
//         TAxLCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluX2FhcyJ9.dI95
//         8fYhz2RxcnXbeTgmOVTykW6en315lAOofh4kljIAiYJlCzg7EJsr5TysDynlXN1J
//         CFHxLXOv2mLwx-VCXUPRvynTuENFUxNxnj13a1SlesYWQMt8cJUUfIHuz8pFWA71
//         OIqdR6LO7z98A1HCaM6UDusskw53EpUOx2ZYm_WTxWdnI0Gp-VKMDCt7JlR497o8
//         o5xBpiuoeJDd_7fl5lfaOdkocedisAtwqhDxAsMhmlxfJ7CeR5yic1YmVN9kDwjA
//         l_IF248K12Vu7QiFsuTt5NJUqyOCWHS1igv_U67-55o5sR37xciDgPg-z1bGIdTm
//         g-GxCZQNbo5I6zr5E-_GgzsBfbIWvN_sxFXq7pN3CN7wvCfnEGXsW4coThT2PS6V
//         roDctDvds396GUcr1Ra077t8q_ETPStLcuKyAvH994uzyVIIXKZnyb9mjDdYU168
//         4G0f6M2HpZoo9DZxeQlGf4RmZVqODSW2FH78f0x0a3UTsLsV02Si0KU1GaI2
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/token
// x-sample-call-input: |
//    {
//       "username" : "admin@aas",
//       "password" : "aasAdminPass"
//    }
// x-sample-call-output: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImYwY2UyNzhhMGM0OGI5NjE3YzQxNzViYmMz
//         ZWIyNThjNDEwYzI2NzUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZ
//         SI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsI
//         m5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc
//         2VyUm9sZU1hbmFnZXIifV0sImV4cCI6MTU3OTE4ODEwMSwiaWF0IjoxNTc5MTgwO
//         TAxLCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluX2FhcyJ9.dI95
//         8fYhz2RxcnXbeTgmOVTykW6en315lAOofh4kljIAiYJlCzg7EJsr5TysDynlXN1J
//         CFHxLXOv2mLwx-VCXUPRvynTuENFUxNxnj13a1SlesYWQMt8cJUUfIHuz8pFWA71
//         OIqdR6LO7z98A1HCaM6UDusskw53EpUOx2ZYm_WTxWdnI0Gp-VKMDCt7JlR497o8
//         o5xBpiuoeJDd_7fl5lfaOdkocedisAtwqhDxAsMhmlxfJ7CeR5yic1YmVN9kDwjA
//         l_IF248K12Vu7QiFsuTt5NJUqyOCWHS1igv_U67-55o5sR37xciDgPg-z1bGIdTm
//         g-GxCZQNbo5I6zr5E-_GgzsBfbIWvN_sxFXq7pN3CN7wvCfnEGXsW4coThT2PS6V
//         roDctDvds396GUcr1Ra077t8q_ETPStLcuKyAvH994uzyVIIXKZnyb9mjDdYU168
//         4G0f6M2HpZoo9DZxeQlGf4RmZVqODSW2FH78f0x0a3UTsLsV02Si0KU1GaI2
// ---

// swagger:operation POST /custom-claims-token Token getCustomClaimsJwtToken
// ---
// description: |
//   Creates a new bearer token that can be used in the Authorization header for other API
//   requests. Bearer token Authorization is required when requesting custom claims token
//   from Authservice.
//
// security:
//  - bearerAuth: []
// consumes:
// - application/json
// produces:
// - application/jwt
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/CustomClaims"
// responses:
//   '200':
//     description: Successfully created the bearer token.
//     schema:
//       type: string
//       example: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImZiNzE2YmE0MjkwODg2NGJlZWQ1ZmNmODZi
//         MTM1MjNhYjg0Yzc1ZTkiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sibmFtZSI6I
//         khvc3REYXRhVXBkYXRlciIsInNlcnZpY2UiOiJTQ1MifSx7Im5hbWUiOiJIb3N0R
//         GF0YVJlYWRlciIsInNlcnZpY2UiOiJTQ1MifSx7Im5hbWUiOiJIb3N0RGF0YVVwZ
//         GF0ZXIiLCJzZXJ2aWNlIjoiU0hWUyJ9XSwiZXhwIjoxNjEzOTkwMzMyLCJpYXQiO
//         jE2MTM5ODY3MDIsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiMDAwMDAwM
//         DAtODg4Ny0wZjE1LTAxMDYtMTAyNGE1YTVhNWE1In0.uE5DMDGQfrP9VMb8ORhD8
//         QioOZezt9W_z09JgZSeQR_tGmVrSguOO6HnDouSnvIA1d-h1yyvoMDyMdzh0XbaS
//         zki0fFMRw5aU3ppWZLeDJnyukZlk155XTmF8CeVB16s3KF22OQlsIDSQamr7w0KR
//         VWQHmrw4QTdszHhImqVd1Xu71_z1guWTOenFqkxCfs9oeOidAw1saSvGif4TJ1hV
//         Waoisj6Bdc6BdzNqDspZ54MTXaq0v50s0mWKnZeEkOrxrjB97zhlRigMasOgZJO1
//         Wo3GC1Mg1SlLCHB-DVzgE9Fso627spe16GCW81tG4K1fFHllu-njua4kQLyhSgxS
//         gC4MyccuZpnQfGOsmGkR-GiTWpjmaYl0q4pjXoQLqaDksYa0tqZC0IhaauSWcRCS
//         PLXFXTIa55e53dYRPt3mf3LllNtiMsMBTOaX075MQ77TCqmgT-0cAlsB-VlqfiYP
//         t8F6Qsn2ELaG3Yeb7Y5mN-5Ecq4dxf9WtJFaPQhtslO
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/custom-claims-token
// x-sample-call-input: |
//    {
//        "subject": "00000000-8887-0f15-0106-1024a5a5a5a5",
//        "validity_seconds": 86400,
//        "claims": {
//            "roles": [{
//                "service": "SCS",
//                "name": "HostDataUpdater"
//            },
//            {
//                "service": "SCS",
//                "name": "HostDataReader"
//            },
//            {
//                "service": "SHVS",
//                "name": "HostDataUpdater"
//            }]
//        }
//    }
// x-sample-call-output: |
//         eyJhbGciOiJSUzM4NCIsImtpZCI6ImZiNzE2YmE0MjkwODg2NGJlZWQ1ZmNmODZi
//         MTM1MjNhYjg0Yzc1ZTkiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sibmFtZSI6I
//         khvc3REYXRhVXBkYXRlciIsInNlcnZpY2UiOiJTQ1MifSx7Im5hbWUiOiJIb3N0R
//         GF0YVJlYWRlciIsInNlcnZpY2UiOiJTQ1MifSx7Im5hbWUiOiJIb3N0RGF0YVVwZ
//         GF0ZXIiLCJzZXJ2aWNlIjoiU0hWUyJ9XSwiZXhwIjoxNjEzOTkwMzMyLCJpYXQiO
//         jE2MTM5ODY3MDIsImlzcyI6IkFBUyBKV1QgSXNzdWVyIiwic3ViIjoiMDAwMDAwM
//         DAtODg4Ny0wZjE1LTAxMDYtMTAyNGE1YTVhNWE1In0.uE5DMDGQfrP9VMb8ORhD8
//         QioOZezt9W_z09JgZSeQR_tGmVrSguOO6HnDouSnvIA1d-h1yyvoMDyMdzh0XbaS
//         zki0fFMRw5aU3ppWZLeDJnyukZlk155XTmF8CeVB16s3KF22OQlsIDSQamr7w0KR
//         VWQHmrw4QTdszHhImqVd1Xu71_z1guWTOenFqkxCfs9oeOidAw1saSvGif4TJ1hV
//         Waoisj6Bdc6BdzNqDspZ54MTXaq0v50s0mWKnZeEkOrxrjB97zhlRigMasOgZJO1
//         Wo3GC1Mg1SlLCHB-DVzgE9Fso627spe16GCW81tG4K1fFHllu-njua4kQLyhSgxS
//         gC4MyccuZpnQfGOsmGkR-GiTWpjmaYl0q4pjXoQLqaDksYa0tqZC0IhaauSWcRCS
//         PLXFXTIa55e53dYRPt3mf3LllNtiMsMBTOaX075MQ77TCqmgT-0cAlsB-VlqfiYP
//         t8F6Qsn2ELaG3Yeb7Y5mN-5Ecq4dxf9WtJFaPQhtslO
// ---
