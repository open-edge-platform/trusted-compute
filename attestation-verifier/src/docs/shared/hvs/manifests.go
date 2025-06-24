/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

// Manifests API request payload
// swagger:parameters ManifestRequest
type Manifest struct {
	// in:body
	Body model.Manifest
}

// ---
//
// swagger:operation GET /manifests Manifests Get-Software-Manifest
// ---
//
// description: |
//              A manifest is a list of files/directories/symlinks that are to be measured.
//              Creates the manifest from a software flavor which is retrieved using the flavor uuid and returns it.
//
// x-permissions: flavors:search
// security:
//  - bearerAuth: []
// produces:
// - application/xml
// parameters:
// - name: id
//   description: Flavor ID
//   in: query
//   type: string
//   format: uuid
//   required: true
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/xml
// responses:
//   '200':
//     description: Successfully generated manifest for the software flavor.
//     content:
//       application/xml
//     schema:
//       $ref: "#/definitions/Manifest"
//   '400':
//     description: Invalid flavor ID provided
//   '415':
//     description: Invalid Accept Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/manifests?id=f66ac31d-124d-418e-8200-2abf414a9adf
// x-sample-call-output: |
//      <Manifest xmlns="" Label="Sample_label" Uuid="f66ac31d-124d-418e-8200-2abf414a9adf" DigestAlg="SHA384">
//            <Dir Include=".*" Path="/usr/local/bin"></Dir>
//            <File Path="/usr/local/bin/wget"></File>
//      </Manifest>
// ---
