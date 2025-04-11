/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/controllers"
	"net/http"
)

func SetVersionRoutes(router *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:SetVersionRoutes() Entering")
	defer defaultLog.Trace("router/version:SetVersionRoutes() Leaving")
	versionController := controllers.VersionController{}

	router.Handle("/version", versionController.GetVersion()).Methods(http.MethodGet)
	return router
}
