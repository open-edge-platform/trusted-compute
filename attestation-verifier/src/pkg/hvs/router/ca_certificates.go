/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"net/http"
)

func SetCaCertificatesRoutes(router *mux.Router, certStore *crypt.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Entering")
	defer defaultLog.Trace("router/ca_certificates:SetCaCertificatesRoutes() Leaving")

	caCertController := controllers.CaCertificatesController{CertStore: certStore}

	router.Handle("/ca-certificates/{certType}", ErrorHandler(JsonResponseHandler(caCertController.Retrieve))).Methods(http.MethodGet)
	router.Handle("/ca-certificates", ErrorHandler(ResponseHandler(caCertController.SearchPem))).Methods(http.MethodGet).Headers("Accept", constants.HTTPMediaTypePemFile)
	router.Handle("/ca-certificates", ErrorHandler(JsonResponseHandler(caCertController.Search))).Methods(http.MethodGet)
	return router
}
