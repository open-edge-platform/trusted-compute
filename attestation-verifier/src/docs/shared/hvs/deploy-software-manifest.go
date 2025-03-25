/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

// DeploySoftwareManifest API request payload
// swagger:parameters DeploySoftwareManifest
type DeployManifestRequest struct {
	// in:body
	Body hvs.DeployManifestRequest
}

// ---
//
// swagger:operation POST /rpc/deploy-software-manifest Deploy-Software-Manifest Deploy-Software-Manifest
// ---
//
// description: |
//              A manifest is a list of files/directories/symlinks that are to be measured. The manifest can be deployed or pushed directly to the host using the REST API described here. The Verification Service exposes this REST API to create manifest from flavor retrieved from database based cn the flavor id provided by the user and deploy it to the host whose information has been provided in the input as host id (if host is already registered to Verification Service).
//              Creates the manifest from a software flavor which is retrieved using the flavor uuid and deploys it to the host based on the hostId provided as parameter.
//
//
//
// x-permissions: software_flavors:deploy
// security:
//  - bearerAuth: []
// consumes:
// - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/DeployManifestRequest"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '200':
//     description: Successfully deployed application manifest to host.
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Content-Type Header
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/rpc/deploy-software-manifest
// x-sample-call-input: |
//      {
//         "flavor_id":"436c729a-e3a6-4d71-8ea2-fc3b459bd4b3",
//         "host_id":"d9d43923-05ae-4c8a-a64f-eba02473010d"
//      }
// ---
