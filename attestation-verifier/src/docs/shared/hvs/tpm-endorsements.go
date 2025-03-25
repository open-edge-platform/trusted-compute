/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// TpmEndorsement response payload
// swagger:parameters TpmEndorsement
type TpmEndorsement struct {
	// in:body
	Body hvs.TpmEndorsement
}

// TpmEndorsementCollection response payload
// swagger:parameters TpmEndorsementCollection
type TpmEndorsementCollection struct {
	//	in:body
	Body hvs.TpmEndorsementCollection
}

// ---

// swagger:operation GET /tpm-endorsements TpmEndorsements Search-TpmEndorsement
// ---
// description: |
//   An Endorsement certificate is used to bind an identity or specific security attributes to a TPM.
//
// x-permissions: tpm_endorsements:search
// security:
//   - bearerAuth: []
// produces:
//   - application/json
// parameters:
//   - name: id
//     description: Tpm endorsement ID
//     in: query
//     type: string
//     format: uuid
//     required: false
//   - name: hardwareUuidEqualTo
//     description: hardware UUID of the host to which the Ek is associated.
//     in: query
//     type: string
//     format: uuid
//     required: false
//   - name: limit
//     description: Limit of the number of items in a page.
//     in: query
//     type: integer
//     required: false
//     default: 1000
//   - name: afterId
//     description: Next row id after which db must be queried
//     in: query
//     type: integer
//     required: false
//   - name: issuerEqualTo
//     description: Issuer name.
//     in: query
//     type: string
//     required: false
//   - name: issuerContains
//     description: Substring of issuer name.
//     in: query
//     type: string
//     format: string
//     required: false
//   - name: revokedEqualTo
//     description: Boolean value to indicate status of the ek certificate. Default value is false.
//     in: query
//     type: boolean
//     required: false
//   - name: commentEqualTo
//     description: The complete comment associated with the EK.
//     in: query
//     type: string
//     required: false
//   - name: commentContains
//     description: Substring of comment associated with the EK.
//     in: query
//     type: string
//     required: false
//   - name: Accept
//     description: Accept header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
// responses:
//   "200":
//     description: Successfully retrieved the tpm-endorsements.
//     content: application/json
//     schema:
//       $ref: "#/definitions/TpmEndorsementCollection"
//   '400':
//     description: Invalid search criteria provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tpm-endorsements?hardwareUuidEqualTo=80e54342-94f2-e711-906e-001560a04062
// x-sample-call-output: |
//   {
//        "tpm_endorsements": [
//           {
//               "id"            		: "d7e24dd4-76c0-4384-a8b0-09552ebaa1a1",
//               "hardware_uuid" 		: "80e54342-94f2-e711-906e-001560a04062",
//               "issuer"       		: "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//               "revoked"       		: false,
//               "certificate"   		: "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//               "comment"       		: "registered by trust agent"
//               "certificate_digest" : "da8e9c68faf66d2634a4cbe14534a1916db261f401ffaffd42dc901eae33dd57695f365a31d19da67e4cebf1491dea60"
//              }
//          ]
//      }

// ---

// swagger:operation POST /tpm-endorsements TpmEndorsements Create-TpmEndorsement
// ---
// description: |
//   Creates a TpmEndorsement.
//
//   The serialized TpmEndorsement Go struct object represents the content of the request body.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | certificate                    | The Base64 encoded Endorsement Certificate |
//    | hardwareUuid                   | Hardware UUID of the host associated with the certificate. Can be retrieved by calling into the GET method on the host with a specific filter criteria. |
//    | issuer                         | The OEM of the TPM. Refer to sample issuer input for attributes. |
//    | revoked                        | Validity status of the EK certificate. Default is false (Optional) |
//    | comment                        | Comments for the certificate.  (Optional)|
//
//
// x-permissions: tpm_endorsements:create
// security:
//   - bearerAuth: []
// produces:
//   - application/json
// consumes:
//   - application/json
// parameters:
//   - name: request body
//     required: true
//     in: body
//     schema:
//       "$ref": "#/definitions/TpmEndorsement"
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
//   '201':
//     description: Successfully created the tpm-endorsement.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/TpmEndorsement"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https:hvs.com:8443/hvs/v2/tpm-endorsements
// x-sample-call-input: |
//   {
//             "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
//             "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//             "revoked"       : false,
//             "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//             "comment"       : "registered by trust agent"
//   }
// x-sample-call-output: |
//   {
//       "id"            : "35adea3b-9f35-4e15-8c82-dee2f8880599",
//       "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
//       "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//       "revoked"       : false,
//       "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//       "comment"       : "registered by trust agent",
//       "certificate_digest": "da8e9c68faf66d2634a4cbe14534a1916db261f401ffaffd42dc901eae33dd57695f365a31d19da67e4cebf1491dea60"
//   }

// ---

// swagger:operation PUT /tpm-endorsements/{tpm-endorsement_id} TpmEndorsements Update-TpmEndorsement
// ---
// description: |
//   Update tpm endorsement certificate.
//
//   The serialized TpmEndorsement Go struct object represents the content of the request body.
//
//    | Attribute                      | Description|
//    |--------------------------------|------------|
//    | certificate                    | The Base64 encoded Endorsement Certificate |
//    | hardwareUuid                   | Hardware UUID of the host associated with the certificate. Can be retrieved by calling into the GET method on the host with a specific filter criteria. |
//    | issuer                         | The OEM of the TPM. Refer to sample issuer input for attributes. |
//    | revoked                        | Validity status of the EK certificate. |
//    | comment                        | Comments for the certificate. |
//
//
// x-permissions: tpm_endorsements:store
// security:
//   - bearerAuth: []
// produces:
//   - application/json
// consumes:
//   - application/json
// parameters:
//   - name: tpm-endorsement_id
//     description: Unique ID of the TpmEndorsement.
//     in: path
//     required: true
//     type: string
//     format: uuid
//   - name: request body
//     required: true
//     in: body
//     schema:
//       "$ref": "#/definitions/TpmEndorsement"
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
//     description: Successfully updated the tpm-endorsement.
//     content: application/json
//     schema:
//       $ref: "#/definitions/TpmEndorsement"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type/Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tpm-endorsements/ebec68d1-a78f-4b66-b643-d80ba44e7fc0
// x-sample-call-input: |
//   {
//             "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
//             "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//             "revoked"       : false,
//             "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//             "comment"       : "registered by trust agent"
//   }
// x-sample-call-output: |
//   {
//        "id"            		: "ebec68d1-a78f-4b66-b643-d80ba44e7fc0",
//        "hardware_uuid" 		: "0002bfac-9ac5-e711-906e-00163566263e",
//        "issuer"        		: "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//        "revoked"       		: false,
//        "certificate"   		: "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//        "comment"       		: "registered by trust agent",
//        "certificate_digest"	: "da8e9c68faf66d2634a4cbe14534a1916db261f401ffaffd42dc901eae33dd57695f365a31d19da67e4cebf1491dea60"
//   }

// ---

// swagger:operation GET /tpm-endorsements/{tpm-endorsement_id} TpmEndorsements Retrieve-TpmEndorsement
// ---
// description: |
//   Retrieves a tpm-endorsement.
//   Returns - The serialized TpmEndorsement Go struct object that was retrieved
// x-permissions: tpm_endorsements:retrieve
// security:
//   - bearerAuth: []
// produces:
//   - application/json
// parameters:
//   - name: tpm-endorsement_id
//     description: Unique ID of the TpmEndorsement.
//     in: path
//     required: true
//     type: string
//     format: uuid
//   - name: Accept
//     description: Accept header
//     in: header
//     type: string
//     required: true
//     enum:
//       - application/json
// responses:
//   '200':
//     description: Successfully retrieved the TpmEndorsement.
//     content: application/json
//     schema:
//       $ref: "#/definitions/TpmEndorsement"
//   '404':
//     description: No relevant TpmEndorsement record found.
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error.
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tpm-endorsements/826501bd-3c75-4839-a08f-db5f744f8498
// x-sample-call-output: |
//   {
//        "id"            : "35adea3b-9f35-4e15-8c82-dee2f8880599",
//        "hardware_uuid" : "0002bfac-9ac5-e711-906e-00163566263e",
//        "issuer"        : "C=DE,O=Infineon Technologies AG,OU=OPTIGA(TM) TPM2.0,CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007",
//        "revoked"       : false,
//        "certificate"   : "MIIEnDCCA4SgAwIBAgIEUilBVDANBgkqhkiG9w0BAQsFADCBgzELMAk...NBgkqhkiG9w0BAQsFADCBgzELMAk==",
//        "comment"       : "registered by trust agent",
//        "certificate_digest" : "da8e9c68faf66d2634a4cbe14534a1916db261f401ffaffd42dc901eae33dd57695f365a31d19da67e4cebf1491dea60"
//   }

// ---

// swagger:operation DELETE /tpm-endorsements/{tpm-endorsement_id} TpmEndorsements Delete-TpmEndorsement
// ---
//  description: |
//    Deletes a TpmEndorsement.
//  x-permissions: tpm_endorsements:delete
//  security:
//    - bearerAuth: []
//  parameters:
//    - name: tpm-endorsement_id
//      description: Unique ID of the TpmEndorsement.
//      in: path
//      required: true
//      type: string
//      format: uuid
//  responses:
//    '204':
//      description: Successfully deleted the TpmEndorsement.
//    '404':
//      description: No relevant TpmEndorsement record found.
//    '500':
//      description: Internal server error
//  x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/tpm-endorsements/826501bd-3c75-4839-a08f-db5f744f8498
