/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"net/http"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/controllers"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/gorilla/mux"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/middleware"
)

const (
	getAIKPerm             = "aik:retrieve"
	getAIKCAPerm           = "aik_ca:retrieve"
	getBindingKeyPerm      = "binding_key:retrieve"
	getDAAPerm             = "daa:retrieve"
	getHostInfoPerm        = "host_info:retrieve"
	postDeployManifestPerm = "deploy_manifest:create"
	postAppMeasurementPerm = "application_measurement:create"
	postDeployTagPerm      = "deploy_tag:create"
	postQuotePerm          = "quote:create"
)

var (
	log    = commLog.GetDefaultLogger()
	secLog = commLog.GetSecurityLogger()
)

var cacheTime, _ = time.ParseDuration(constants.JWTCertsCacheTime)
var seclog = commLog.GetSecurityLogger()

func InitRoutes(trustedJWTSigningCertsDir, trustedCaCertsDir string, requestHandler common.RequestHandler) *mux.Router {
	// Register routes...
	router := mux.NewRouter()
	// ISECL-8715 - Prevent potential open redirects to external URLs
	router.SkipClean(true)
	defineSubRoutes(router, trustedJWTSigningCertsDir, trustedCaCertsDir, requestHandler)
	return router
}

func defineSubRoutes(router *mux.Router, trustedJWTSigningCertsDir, trustedCaCertsDir string, requestHandler common.RequestHandler) {
	log.Trace("router/router:defineSubRoutes() Entering")
	defer log.Trace("router/router:defineSubRoutes() Leaving")

	serviceApi := "/" + constants.ApiVersion
	subRouter := router.PathPrefix(serviceApi).Subrouter()
	subRouter = setVersionRoutes(subRouter)

	subRouter = router.PathPrefix(serviceApi).Subrouter()
	subRouter.Use(middleware.NewTokenAuth(trustedJWTSigningCertsDir, trustedCaCertsDir, fnGetJwtCerts, cacheTime))
	subRouter.HandleFunc("/aik", ErrorHandler(RequiresPermission(controllers.GetAik(requestHandler), []string{getAIKPerm}))).Methods(http.MethodGet)
	subRouter.HandleFunc("/host", ErrorHandler(RequiresPermission(controllers.GetPlatformInfo(requestHandler, constants.PlatformInfoFilePath), []string{getHostInfoPerm}))).Methods(http.MethodGet)
	subRouter.HandleFunc("/tpm/quote", ErrorHandler(RequiresPermission(controllers.GetTpmQuote(requestHandler), []string{postQuotePerm}))).Methods(http.MethodPost)
	subRouter.HandleFunc("/binding-key-certificate", ErrorHandler(RequiresPermission(controllers.GetBindingKeyCertificate(requestHandler), []string{getBindingKeyPerm}))).Methods(http.MethodGet)
	subRouter.HandleFunc("/tag", ErrorHandler(RequiresPermission(controllers.SetAssetTag(requestHandler), []string{postDeployTagPerm}))).Methods(http.MethodPost)
	subRouter.HandleFunc("/host/application-measurement", ErrorHandler(RequiresPermission(controllers.GetApplicationMeasurement(requestHandler), []string{postAppMeasurementPerm}))).Methods(http.MethodPost)
	subRouter.HandleFunc("/deploy/manifest", ErrorHandler(RequiresPermission(controllers.DeployManifest(requestHandler), []string{postDeployManifestPerm}))).Methods(http.MethodPost)
}

func setVersionRoutes(router *mux.Router) *mux.Router {
	log.Trace("router/router:setVersionRoutes() Entering")
	defer log.Trace("router/router:setVersionRoutes() Leaving")

	router.HandleFunc("/version", ErrorHandler(controllers.GetVersion())).Methods(http.MethodGet)
	return router
}
