/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

// FlavorFromAppManifest API request payload
// swagger:parameters ManifestRequest
type ManifestRequest struct {
	// in:body
	Body hvs.ManifestRequest
}

// FlavorFromAppManifest API response payload
// swagger:parameters Flavor
type Flavor struct {
	// in:body
	Body hvs.Flavor
}

// ---
//
// swagger:operation POST /flavor-from-app-manifest Flavor-From-App-Manifest Create-Software-Flavor
// ---
//
// description: |
//      A flavor is a set of measurements and metadata organized in a flexible format that allows for ease of further extension. The measurements included in the flavor pertain to various hardware, software and feature categories, and their respective metadata sections provide descriptive information.
//
//      When a flavor is created, it is associated with a flavor group. This means that the measurements for that flavor type are deemed acceptable to obtain a trusted status. If a host, associated with the same flavor group, matches the measurements contained within that flavor, the host is trusted for that particular flavor category (dependent on the flavor group policy). If no flavor group name is defined in input, flavor is, by default, associated with automatic flavor group.
//
//      A manifest is a list of files/directories/symlinks that are to be measured. The manifest provided can be used to create SOFTWARE flavor only.
//
//      The Verification Service exposes this REST API to create and store SOFTWARE flavor as per the manifest provided.
//
//      The serialized ManifestRequest Go struct object represents the content of the request body.
//
//        | Attribute                      | Description                                     |
//        |--------------------------------|-------------------------------------------------|
//        | hostId                         | (Optional) The host id is used to fetch the connection string from database. If not provided, 'connectionString' needs to be provided.|
//        | connectionString               | (Optional) The connection string is of the form <b>https://tagent-ip:1443"</b>. If not provided, 'hostId' needs to be provided.|
//        | flavorgroupNames               | (Optional) Name of the flavor groups the created flavor needs to be associated to. If not provided, flavor is associated to default flavor group.|
//        | Manifest                       | Application manifest for which flavor needs to be created. |
//
//
// x-permissions: software_flavors:create
// security:
//  - bearerAuth: []
// produces:
// - application/json
// consumes:
// - application/xml
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/ManifestRequest"
// - name: Content-Type
//   description: Content-Type header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/xml
// - name: Accept
//   description: Accept header
//   in: header
//   type: string
//   required: true
//   enum:
//     - application/json
// responses:
//   '201':
//     description: Successfully created the software flavor.
//     content:
//       application/json
//     schema:
//       $ref: "#/definitions/Flavor"
//   '400':
//     description: Invalid request body provided
//   '415':
//     description: Invalid Accept/Content-Type Header in Request
//   '500':
//     description: Internal server error
//
// x-sample-call-endpoint: https://hvs.com:8443/hvs/v2/flavor-from-app-manifest
// x-sample-call-input: |
//  `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
//      <connectionString>intel:https://tagent-ip:1443</connectionString>
//      <Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="Sample_Label">
//          <Dir Include=".*" Exclude="" Path="/usr/local/bin"/>
//          <File Path="/usr/local/bin/wget"/>
//      </Manifest>
//  </ManifestRequest>`
//
// x-sample-call-output: |
//   {
//      "meta": {
//          "schema": {
//              "uri": "lib:wml:measurements:1.0"
//          },
//          "id": "5226d7f1-8105-4f98-9fe2-82220044b514",
//          "description": {
//              "flavor_part": "SOFTWARE",
//              "label": "ISL_Applications1234",
//              "digest_algorithm": "SHA384"
//          }
//      },
//      "software": {
//          "measurements": {
//              "opt-trustagent-bin": {
//                  "type": "directoryMeasurementType",
//                  "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
//                  "Path": "/opt/trustagent/bin",
//                  "Include": ".*"
//              },
//              "opt-trustagent-bin-module_analysis_da.sh": {
//                  "type": "fileMeasurementType",
//                  "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
//                  "Path": "/opt/trustagent/bin/module_analysis_da.sh"
//              }
//          },
//          "cumulative_hash": "be7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f"
//      }
//   }
// ---
