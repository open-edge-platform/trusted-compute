/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
)

// SetFlavorRoutes registers routes for flavors
func SetFlavorRoutes(router *mux.Router, store *postgres.DataStore, flavorGroupStore domain.FlavorGroupStore, certStore *crypt.CertificatesStore, hostTrustManager domain.HostTrustManager, flavorControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavors:SetFlavorRoutes() Entering")
	defer defaultLog.Trace("router/flavors:SetFlavorRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	tagCertStore := postgres.NewTagCertificateStore(store)
	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)
	flavorController := controllers.NewFlavorController(flavorStore, flavorGroupStore, hostStore, tagCertStore, hostTrustManager, certStore, flavorControllerConfig, flavorTemplateStore)

	flavorIdExpr := fmt.Sprintf("%s%s", "/flavors/", validation.IdReg)

	router.Handle("/flavors",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorController.Create),
			[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
		Methods(http.MethodPost)

	router.Handle("/flavors",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorController.Search),
			[]string{constants.FlavorSearch}))).Methods(http.MethodGet)

	router.Handle(flavorIdExpr,
		ErrorHandler(PermissionsHandler(ResponseHandler(flavorController.Delete),
			[]string{constants.FlavorDelete}))).Methods(http.MethodDelete)

	router.Handle(flavorIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorController.Retrieve),
			[]string{constants.FlavorRetrieve}))).Methods(http.MethodGet)

	return router
}
