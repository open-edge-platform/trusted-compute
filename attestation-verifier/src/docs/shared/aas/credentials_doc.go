/*
 *  Copyright (C) 2021 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package aas

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

// CreateCredentialsReq request payload
// swagger:parameters CreateCredentialsReq
type CreateCredentialsReq struct {
	// in:body
	Body aas.CreateCredentialsReq
}

// ---
//
// swagger:operation POST /credentials Credentials CreateCredentials
// ---
//
// description: |
//   Creates a new credential on AAS and sends it out over response to be accessed and used by the client
//   to authenticate and authorize itself to a service.
//   The credential creation request has a parameter called "type" which is basically the type of the component
//   for which the credential needs to be generated. The only supported values for that are "HVS" or "TA" which
//   stands for Host Verification Service and Trust Agent. Any other value provided will result in bad request.
//
// x-permissions: credential:create
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - text/plain
// parameters:
//  - name: request body
//    required: true
//    in: body
//    schema:
//      "$ref": "#/definitions/CreateCredentialsReq"
// responses:
//   '201':
//      description: Successfully created the credentials.
//   '400':
//      description: Bad request.
//   '401':
//      description: Unauthorized.
//   '500':
//      description: Internal Server Error.
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/credentials
// x-sample-call-input: |
//   {
//    	"type": "TA",
//    	"parameters": {
//        	"host-id": "<TA FQDN>"
//   	 }
//   }
// x-sample-call-output: |
//      -----BEGIN NATS USER JWT-----
//      eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJleHAiOjE2MjIxMDk1NzEsImp0aSI6IlhIVEhDTFdDTE5YV01ER0tLTE5aSU9GQUdGQUlDTVhRNUgyN0ZUSUhHSVBPNVBUQUE2REEiLCJpYXQiOjE2MjE5MzY3NzEsImlzcyI6IkFBQTZPTU1HR0FNSFAzTlZVU0dBQkkyVVRBN1hIS0JHTEpOTk9KWERaQkk2NU5HVUpXNEFHSEZLIiwic3ViIjoiVUNUTVE1TUhBUE5KU1NQSlJFWk1ZV1dON09NRFpESEZPNlI0N1BXTUc2WlJRQlNSNUpKRk5UVjYiLCJuYXRzIjp7InB1YiI6eyJhbGxvdyI6WyJ0cnVzdC1hZ2VudC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIl19LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.eHyGimM4sItxDcfqhEVzhCON8e0qasOT_QX1sxdM0mG9Is_TjK144Pz8U_Ut1jQ7czAi1gzAQZT-fBbyxhw_CA
//      ------END NATS USER JWT------
//
//      ************************* IMPORTANT *************************
//      NKEY Seed printed below can be used to sign and prove identity.
//      NKEYs are sensitive and should be treated as secrets.
//
//      -----BEGIN USER NKEY SEED-----
//      SUAE6WDHNRTCY55TBJUMZLRVLWGZXFE7J2O6IKMQDBX4MQDQE5QVBU4NXU
//      ------END USER NKEY SEED------
//
//      *************************************************************
// ---
