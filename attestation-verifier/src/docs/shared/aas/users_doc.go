/*
 *  Copyright (C) 2020 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

// UserCreateInfo request payload
// swagger:parameters UserCreateInfo
type UserCreateInfo struct {
	// in:body
	Body aas.UserCreate
}

// UserResponse response payload
// swagger:parameters UserResponse
type UserResponse struct {
	// in:body
	Body aas.UserCreateResponse
}

type UsersResponse []aas.UserCreateResponse

// UsersResponse response payload
// swagger:parameters UsersResponse
type SwaggUsersResponse struct {
	// in:body
	Body UsersResponse
}

type UserPermissions []aas.PermissionInfo

// UserPermissions response payload
// swagger:parameters UserPermissions
type SwaggUserPermissions struct {
	// in:body
	Body UserPermissions
}

// PasswordChangeInfo request payload
// swagger:parameters PasswordChangeInfo
type PasswordChangeInfo struct {
	// in:body
	Body aas.PasswordChange
}

// RoleIDsInfo request payload
// swagger:parameters RoleIDsInfo
type RoleIDsInfo struct {
	// in:body
	Body aas.RoleIDs
}

type UserRoleResponse struct {
	Role_id string `json:"role_id"`
	aas.RoleInfo
}

// UserRoleResponse response payload
// swagger:parameters UserRoleResponse
type SwaggUserRoleResponse struct {
	// in:body
	Body UserRoleResponse
}

type UserRolesResponse []UserRoleResponse

// UserRolesResponse response payload
// swagger:parameters UserRolesResponse
type SwaggUserRolesResponse struct {
	// in:body
	Body UserRolesResponse
}

// swagger:operation POST /users Users createUser
// ---
//
// description: |
//   Creates a new user in the Authservice database. User can be one among the service users,
//   user with install permissions or administrative user. An appropriate username and password
//   should be provided to create the user. A valid bearer token should be provided to
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
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/UserCreate"
// responses:
//   '201':
//     description: Successfully created the user with the given username and password.
//     schema:
//       "$ref": "#/definitions/UserCreateResponse"
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/users
// x-sample-call-input: |
//    {
//       "username" : "vsServiceUser",
//       "password" : "vsServicePass"
//    }
// x-sample-call-output: |
//       {
//          "user_id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
//          "username" : "vsServiceUser"
//       }
// ---

// swagger:operation GET /users Users queryUsers
// ---
// description: |
//   Retrieves the list of users from the Authservice database. The users can be one among
//   the service users, users with install permissions or administrative users. A valid bearer
//   token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: name
//   description: Username of the user.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the users.
//     schema:
//       "$ref": "#/definitions/UsersResponse"
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/users?name=vsServiceUser
// x-sample-call-output: |
//    [
//       {
//          "user_id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
//          "username" : "vsServiceUser"
//       }
//    ]
// ---

// swagger:operation GET /users/{user_id} Users getUser
// ---
// description: |
//   Retrieves the user details associated with a specified user id from the Authservice
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the user details for the specified user id.
//     schema:
//       "$ref": "#/definitions/UserCreateResponse"
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78
// x-sample-call-output: |
//   {
//      "user_id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
//      "username": "vsServiceUser"
//   }
// ---

// ---
// swagger:operation PATCH /users/{user_id} Users updateUser
// ---
// description: |
//   Updates the username and password associated with a specific user id in the Authservice
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/UserCreate"
// responses:
//   '200':
//     description: |
//       Successfully updated the username and password associated with the specified user id.
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78
// x-sample-call-input: |
//    {
//       "username" : "vsServiceUser",
//       "password" : "vsServicePassNew"
//    }
// x-sample-call-output: |
//    200 OK
// ---

// swagger:operation DELETE /users/{user_id} Users deleteUser
// ---
// description: |
//   Deletes the user details associated with a specfied user id from the Authservice
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully deleted the user.
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78
// x-sample-call-output: |
//    204 No content
// ---

// swagger:operation GET /users/{user_id}/permissions Users queryUserPermissions
// ---
// description: |
//   Retrieves the user permissions associated with a specified user id from the Authservice
//   database. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the user permissions.
//     schema:
//       "$ref": "#/definitions/UserPermissions"
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78/permissions
// x-sample-call-output: |
//    [
//       {
//          "service": "VS",
//          "rules": [
//                     "flavors:search:*",
//                     "hosts:create:*"
//                   ]
//       }
//    ]
// ---

// swagger:operation PATCH /users/changepassword Users changePassword
// ---
// description: |
//   Updates the password for the specified user in the Authservice database.
//
// consumes:
//  - application/json
// parameters:
// - name: request body
//   required: true
//   in: body
//   schema:
//     "$ref": "#/definitions/PasswordChange"
// responses:
//   '200':
//     description: Successfully updated the user password.
//
// x-sample-call-endpoint: https://authservice.com:8444/aas/v1/users/changepassword
// x-sample-call-input: |
//    {
//        "old_password": "vsServicePass",
//        "new_password": "vsUserNewPass",
//        "password_confirm": "vsUserNewPass",
//        "username": "vsServiceUser"
//    }
// x-sample-call-output: |
//    200 No content

// ---

// swagger:operation POST /users/{user_id}/roles UserRoles addUserRoles
// ---
// description: |
//   Assigns the roles to the user associated with the specified user id in the Authservice
//   database. A list of role id's should be provided in the request body which will be assigned to the
//   user. A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: request body
//   required: true
//   in: body
//   schema:
//    "$ref": "#/definitions/RoleIDs"
// responses:
//   '201':
//     description: Successfully assigned the roles to the user.
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78/roles
// x-sample-call-input: |
//    {
//       "role_ids" : [ "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585" ]
//    }
// x-sample-call-output: |
//    201 Created
// ---

// swagger:operation GET /users/{user_id}/roles UserRoles queryUserRoles
// ---
// description: |
//   Retrieves the roles associated with the specified user id based on the provided filter criteria
//   from the Authservice database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: service
//   description: Name of the service.
//   in: query
//   type: string
// - name: name
//   description: Name of the role.
//   in: query
//   type: string
// - name: context
//   description: Context string which contains informations such as CN, SAN and certType.
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
//     description: Successfully retrieved the user roles.
//     schema:
//      "$ref": "#/definitions/UserRolesResponse"
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78/roles?service=CMS
// x-sample-call-output: |
//    [
//       {
//          "role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
//          "service": "CMS",
//          "name": "CertApprover"
//       }
//    ]
// ---

// swagger:operation GET /users/{user_id}/roles/{role_id} UserRoles getUserRoleById
// ---
// description: |
//   Retrieves the specified role associated with a user id from the Authservice database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: role_id
//   description: Unique ID of the role.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '200':
//     description: Successfully retrieved the specified role associated with user.
//     schema:
//      "$ref": "#/definitions/UserRoleResponse"
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78/roles/75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585
// x-sample-call-output: |
//    {
//       "role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
//       "service": "CMS",
//       "name": "CertApprover"
//    }
// ---

// swagger:operation DELETE /users/{user_id}/roles/{role_id} UserRoles deleteUserRole
// ---
// description: |
//   Removes the specified role associated with a user id from the Authservice database.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// parameters:
// - name: user_id
//   description: Unique ID of the user.
//   in: path
//   required: true
//   type: string
//   format: uuid
// - name: role_id
//   description: Unique ID of the role.
//   in: path
//   required: true
//   type: string
//   format: uuid
// responses:
//   '204':
//     description: Successfully removed the specified role associated with user.
//
// x-sample-call-endpoint: |
//    https://authservice.com:8444/aas/v1/users/1fdb39de-7bf4-440e-ad05-286eca933f78/roles/75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585
// x-sample-call-output: |
//    204 No content
// ---
