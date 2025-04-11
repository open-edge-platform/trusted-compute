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

// SetHostRoutes registers routes for hosts
func SetHostRoutes(router *mux.Router, store *postgres.DataStore, hostTrustManager domain.HostTrustManager, hostControllerConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/hosts:SetHostRoutes() Entering")
	defer defaultLog.Trace("router/hosts:SetHostRoutes() Leaving")

	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostCredentialStore := postgres.NewHostCredentialStore(store, hostControllerConfig.DataEncryptionKey)

	hostController := controllers.NewHostController(hostStore, hostStatusStore,
		flavorStore, flavorGroupStore, hostCredentialStore,
		hostTrustManager, hostControllerConfig)

	hostExpr := "/hosts"
	hostIdExpr := fmt.Sprintf("%s/{hId:%s}", hostExpr, validation.UUIDReg)
	flavorgroupExpr := fmt.Sprintf("%s/flavorgroups", hostIdExpr)
	flavorgroupIdExpr := fmt.Sprintf("%s/{fgId:%s}", flavorgroupExpr, validation.UUIDReg)

	router.Handle(hostExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.Create),
		[]string{constants.HostCreate}))).Methods(http.MethodPost)
	router.Handle(hostIdExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.Retrieve),
		[]string{constants.HostRetrieve}))).Methods(http.MethodGet)
	router.Handle(hostIdExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.Update),
		[]string{constants.HostUpdate}))).Methods(http.MethodPut)
	router.Handle(hostIdExpr, ErrorHandler(PermissionsHandler(ResponseHandler(hostController.Delete),
		[]string{constants.HostDelete}))).Methods(http.MethodDelete)
	router.Handle(hostExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.Search),
		[]string{constants.HostSearch}))).Methods(http.MethodGet)

	router.Handle(flavorgroupExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.AddFlavorgroup),
		[]string{constants.HostCreate}))).Methods(http.MethodPost)
	router.Handle(flavorgroupIdExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.RetrieveFlavorgroup),
		[]string{constants.HostRetrieve}))).Methods(http.MethodGet)
	router.Handle(flavorgroupIdExpr, ErrorHandler(PermissionsHandler(ResponseHandler(hostController.RemoveFlavorgroup),
		[]string{constants.HostDelete}))).Methods(http.MethodDelete)
	router.Handle(flavorgroupExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hostController.SearchFlavorgroups),
		[]string{constants.HostSearch}))).Methods(http.MethodGet)

	return router
}
