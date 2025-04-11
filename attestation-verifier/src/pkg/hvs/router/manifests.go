/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"net/http"
)

//SetManifestsRoute registers routes for manifests api
func SetManifestsRoute(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/manifests:SetManifestsRoutes() Entering")
	defer defaultLog.Trace("router/manifests:SetManifestsRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	manifestsController := controllers.NewManifestsController(flavorStore)

	router.Handle("/manifests",
		ErrorHandler(PermissionsHandler(XMLResponseHandler(manifestsController.GetManifest),
			[]string{constants.FlavorSearch}))).Methods(http.MethodGet)

	return router
}
