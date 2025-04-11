/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	"net/http"
)

func SetVersionRoutes(r *mux.Router) *mux.Router {
	defaultLog.Trace("router/version:SetVersion() Entering")
	defer defaultLog.Trace("router/version:SetVersion() Leaving")

	controller := controllers.VersionController{}
	r.Handle("/version", ErrorHandler(ResponseHandler(controller.GetVersion, ""))).Methods(http.MethodGet)
	return r
}
