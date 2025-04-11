/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
)

// SetFlavorGroupRoutes registers routes for flavorgroups
func SetFlavorGroupRoutes(router *mux.Router, store *postgres.DataStore, flavorgroupStore domain.FlavorGroupStore, hostTrustManager domain.HostTrustManager) *mux.Router {
	defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Entering")
	defer defaultLog.Trace("router/flavorgroups:SetFlavorGroupRoutes() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	hostStore := postgres.NewHostStore(store)
	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)
	flavorgroupController := controllers.FlavorgroupController{
		FlavorGroupStore:    flavorgroupStore,
		FlavorTemplateStore: flavorTemplateStore,
		FlavorStore:         flavorStore,
		HostStore:           hostStore,
		HTManager:           hostTrustManager,
	}

	flavorGroupIdExpr := fmt.Sprintf("%s%s", "/flavorgroups/", validation.IdReg)
	router.Handle("/flavorgroups",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.Create),
			[]string{constants.FlavorGroupCreate}))).Methods(http.MethodPost)

	router.Handle("/flavorgroups",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.Search),
			[]string{constants.FlavorGroupSearch}))).Methods(http.MethodGet)

	router.Handle(flavorGroupIdExpr,
		ErrorHandler(PermissionsHandler(ResponseHandler(flavorgroupController.Delete),
			[]string{constants.FlavorGroupDelete}))).Methods(http.MethodDelete)

	router.Handle(flavorGroupIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.Retrieve),
			[]string{constants.FlavorGroupRetrieve}))).Methods(http.MethodGet)

	// routes for FlavorGroupFlavorLink APIs
	fgFlavorLinkCreateSearchExpr := fmt.Sprintf("/flavorgroups/{fgID:%s}/flavors", validation.UUIDReg)
	fgFlavorLinkRetrieveDeleteExpr := fmt.Sprintf("/flavorgroups/{fgID:%s}/flavors/{fID:%s}", validation.UUIDReg, validation.UUIDReg)

	router.Handle(fgFlavorLinkCreateSearchExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.AddFlavor),
			[]string{constants.FlavorGroupCreate}))).Methods(http.MethodPost)

	router.Handle(fgFlavorLinkRetrieveDeleteExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.RetrieveFlavor),
			[]string{constants.FlavorGroupRetrieve}))).Methods(http.MethodGet)

	router.Handle(fgFlavorLinkRetrieveDeleteExpr,
		ErrorHandler(PermissionsHandler(ResponseHandler(flavorgroupController.RemoveFlavor),
			[]string{constants.FlavorGroupDelete}))).Methods(http.MethodDelete)

	router.Handle(fgFlavorLinkCreateSearchExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorgroupController.SearchFlavors),
			[]string{constants.FlavorGroupSearch}))).Methods(http.MethodGet)

	return router
}
