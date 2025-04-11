/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
)

func SetCredentialsRoutes(r *mux.Router, userCredentialValidity time.Duration) *mux.Router {
	defaultLog.Trace("router/credentials_controller:SetCredentialsRoutes() Entering")
	defer defaultLog.Trace("router/jwt_certificate:SetCredentialsRoutes() Leaving")

	controller := controllers.CredentialsController{UserCredentialValidity: userCredentialValidity, AccountSeedFile: consts.AccountSeedFile}
	r.Handle("/credentials", ErrorHandler(PermissionsHandler(ResponseHandler(controller.CreateCredentials,
		"text/plain"), []string{consts.CredentialCreate}))).Methods(http.MethodPost)

	return r
}
