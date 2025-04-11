/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"net/http"
)

func SetCreateCaCertificatesRoutes(router *mux.Router, certStore *crypt.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/create_ca_certificates:SetCreateCaCertificatesRoutes() Entering")
	defer defaultLog.Trace("router/create_ca_certificates:SetCreateCaCertificatesRoutes() Leaving")

	caCertController := controllers.CaCertificatesController{CertStore: certStore}

	router.Handle("/ca-certificates",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(caCertController.Create),
			[]string{constants.CaCertificatesCreate}))).Methods(http.MethodPost)
	return router
}
