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

// SetFlavorTemplateRoutes registers routes for flavor template creation
func SetFlavorTemplateRoutes(router *mux.Router, store *postgres.DataStore, flavorGroupStore domain.FlavorGroupStore) *mux.Router {
	defaultLog.Trace("router/flavortemplate_creation:SetFlavorTemplateRoutes() Entering")
	defer defaultLog.Trace("router/flavortemplate_creation:SetFlavorTemplateRoutes() Leaving")

	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)

	flavorTemplateController := controllers.NewFlavorTemplateController(flavorTemplateStore, flavorGroupStore, constants.CommonDefinitionsSchema, constants.FlavorTemplateSchema)

	flavorTemplateIdExpr := fmt.Sprintf("%s/{ftId:%s}", "/flavor-templates", validation.UUIDReg)
	flavorgroupExpr := fmt.Sprintf("%s/flavorgroups", flavorTemplateIdExpr)
	flavorgroupIdExpr := fmt.Sprintf("%s/{fgId:%s}", flavorgroupExpr, validation.UUIDReg)

	router.Handle("/flavor-templates",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.Create),
			[]string{constants.FlavorTemplateCreate}))).Methods(http.MethodPost)

	router.Handle(flavorTemplateIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.Retrieve),
			[]string{constants.FlavorTemplateRetrieve}))).Methods(http.MethodGet)

	router.Handle("/flavor-templates",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.Search),
			[]string{constants.FlavorTemplateSearch}))).Methods(http.MethodGet)

	router.Handle(flavorTemplateIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.Delete),
			[]string{constants.FlavorTemplateDelete}))).Methods(http.MethodDelete)

	router.Handle(flavorgroupExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.AddFlavorgroup),
		[]string{constants.FlavorTemplateCreate}))).Methods(http.MethodPost)
	router.Handle(flavorgroupIdExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.RetrieveFlavorgroup),
		[]string{constants.FlavorTemplateRetrieve}))).Methods(http.MethodGet)
	router.Handle(flavorgroupIdExpr, ErrorHandler(PermissionsHandler(ResponseHandler(flavorTemplateController.RemoveFlavorgroup),
		[]string{constants.FlavorTemplateDelete}))).Methods(http.MethodDelete)
	router.Handle(flavorgroupExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorTemplateController.SearchFlavorgroups),
		[]string{constants.FlavorTemplateSearch}))).Methods(http.MethodGet)

	return router
}
