/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"net/http"

	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
)

func SetUsersRoutes(r *mux.Router, db domain.AASDatabase) *mux.Router {
	defaultLog.Trace("router/users:SetUsersRoutes() Entering")
	defer defaultLog.Trace("router/users:SetUsersRoutes() Leaving")

	controller := controllers.UsersController{Database: db}

	r.Handle("/users", ErrorHandler(PermissionsHandler(ResponseHandler(controller.CreateUser,
		"application/json"), []string{consts.UserCreate}))).Methods(http.MethodPost)
	r.Handle("/users", ErrorHandler(PermissionsHandler(ResponseHandler(controller.QueryUsers,
		"application/json"), []string{consts.UserSearch}))).Methods(http.MethodGet)
	r.Handle("/users/{id}", ErrorHandler(PermissionsHandler(ResponseHandler(controller.DeleteUser,
		""), []string{consts.UserDelete}))).Methods(http.MethodDelete)
	r.Handle("/users/{id}", ErrorHandler(PermissionsHandler(ResponseHandler(controller.GetUser,
		"application/json"), []string{consts.UserRetrieve}))).Methods(http.MethodGet)
	r.Handle("/users/{id}", ErrorHandler(PermissionsHandler(ResponseHandler(controller.UpdateUser,
		"application/json"), []string{consts.UserStore}))).Methods("PATCH")
	r.Handle("/users/{id}/roles", ErrorHandler(ResponseHandler(controller.AddUserRoles,
		"application/json"))).Methods(http.MethodPost)
	r.Handle("/users/{id}/roles", ErrorHandler(ResponseHandler(controller.QueryUserRoles,
		"application/json"))).Methods(http.MethodGet)
	r.Handle("/users/{id}/permissions", ErrorHandler(ResponseHandler(controller.QueryUserPermissions,
		"application/json"))).Methods(http.MethodGet)
	r.Handle("/users/{id}/roles/{role_id}", ErrorHandler(PermissionsHandler(ResponseHandler(controller.GetUserRoleById,
		"application/json"), []string{consts.UserRoleRetrieve}))).Methods(http.MethodGet)
	r.Handle("/users/{id}/roles/{role_id}", ErrorHandler(PermissionsHandler(ResponseHandler(controller.DeleteUserRole,
		""), []string{consts.UserRoleDelete}))).Methods(http.MethodDelete)

	return r
}

func SetUsersNoAuthRoutes(r *mux.Router, db domain.AASDatabase) *mux.Router {
	defaultLog.Trace("router/users:SetUsersNoAuthRoutes() Entering")
	defer defaultLog.Trace("router/users:SetUsersNoAuthRoutes() Leaving")

	controller := controllers.UsersController{Database: db}
	r.Handle("/users/changepassword", ErrorHandler(ResponseHandler(controller.ChangePassword,
		""))).Methods("PATCH")

	return r
}
