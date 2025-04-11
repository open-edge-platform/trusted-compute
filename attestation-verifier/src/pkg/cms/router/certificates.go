/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/controllers"
	log "github.com/sirupsen/logrus"
	"net/http"
)

// SetCertificatesRoutes is used to set the endpoints for certificate handling APIs
func SetCertificatesRoutes(router *mux.Router, config *config.Configuration) *mux.Router {
	log.Trace("router/certificates:SetCertificatesRoutes() Entering")
	defer log.Trace("router/certificates:SetCertificatesRoutes() Leaving")
	certController := controllers.CertificatesController{Config: config, CaAttribs: constants.CertStoreMap, SerialNo: constants.SerialNumberPath}
	router.HandleFunc("/certificates", certController.GetCertificates).Methods(http.MethodPost)
	return router
}
