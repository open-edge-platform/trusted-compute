/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

// RoleCreateInfo request payload
// swagger:parameters RoleCreateInfo
type RoleCreateInfo struct {
	// in:body
	Body aas.RoleCreate
}

// RoleResponse response payload
// swagger:parameters RoleResponse
type RoleResponse struct {
	// in:body
	Body aas.RoleCreateResponse
}

type RolePermission struct {
	ID   string `json:"permission_id,omitempty" gorm:"primary_key;type:uuid"`
	Rule string `json:"rule"`
}

type RoleTypeInfo struct {
	ID string `json:"role_id,omitempty" gorm:"primary_key;type:uuid"`
	aas.RoleInfo
	Permissions []RolePermission `json:"permissions,omitempty" gorm:"many2many:role_permissions"`
}

type RolesResponse []RoleTypeInfo

// RolesResponse response payload
// swagger:parameters RolesResponse
type SwaggRolesResponse struct {
	// in:body
	Body RolesResponse
}

// swagger:operation POST /roles Roles createRole
// ---
//
// description: |
//   Creates a new role in the Authservice database. An appropriate role name and service
//   should be provided to create the role. A valid bearer token should be provided to
//   authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": '#/definitions/RoleCreate'
// responses:
//   '201':
//      description: Successfully created the role.
//      schema:
//        "$ref": "#/definitions/RoleCreateResponse"
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/roles
// x-sample-call-input: |
//    {
//       "name": "CertApprover",
//       "service": "CMS"
//    }
// x-sample-call-output: |
//    {
//       "role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
//       "service": "CMS",
//       "name": "CertApprover"
//    }
// ---

// swagger:operation GET /roles Roles queryRoles
// ---
// description: |
//   Retrieves the list of roles based on the provided filter criteria from the Authservice database.
//   An appropriate role name, service, context and permissions will be obtained in a json format.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: service
//   description: Service name to which the role is associated.
//   in: query
//   type: string
// - name: name
//   description: Name of the role.
//   in: query
//   type: string
// - name: context
//   description: Context string which contains information such as CN, SAN and certType.
//   in: query
//   type: string
// - name: contextContains
//   description: Partial “context” string.
//   in: query
//   type: string
// - name: allContexts
//   description: Query all contexts.
//   in: query
//   type: boolean
// responses:
//   '200':
//     description: Successfully retrieved the roles.
//     content:
//       application/json
//     schema:
//       "$ref": "#/definitions/RolesResponse"
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/roles?service=CMS
// x-sample-call-output: |
//    [
//       {
//          "role_id": "c18f045d-c40e-417d-b06d-4f1e40c307f3",
//          "service": "CMS",
//          "name" : "CertApprover",
//          "context": "CN=WLS TLS Certificate;SAN=wls.server.com,controller;certType=TLS"
//       }
//    ]
// ---

// swagger:operation DELETE /roles/{role_id} Roles deleteRole
// ---
// description: |
//   Deletes a role associated with the specified role id from the Authservice database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: role_id
//   description: Unique ID of the role.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the role associated with the specified role id.
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/roles/75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585
// x-sample-call-output: |
//    204 No content
// ---

// swagger:operation GET /roles/{role_id} Roles getRole
// ---
// description: |
//   Retrieves the role details associated with a specified role id from the Authservice database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: role_id
//   description: Unique ID of the role.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the role associated with the specified role id.
//     schema:
//       "$ref": "#/definitions/RoleCreateResponse"
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/roles/75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585
// x-sample-call-output: |
//    {
//       "role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
//       "service": "CMS",
//       "name": "CertApprover"
//    }
// ---
