/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
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

// SetESXiClusterRoutes registers routes for esxi cluster apis
func SetESXiClusterRoutes(router *mux.Router, store *postgres.DataStore,
	hostTrustManager domain.HostTrustManager, hostControllerConfig domain.HostControllerConfig) *mux.Router {

	defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Entering")
	defer defaultLog.Trace("router/esxi_cluster:SetESXiClusterRoutes() Leaving")

	esxiClusterStore := postgres.NewESXiCLusterStore(store, hostControllerConfig.DataEncryptionKey)
	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostCredentialStore := postgres.NewHostCredentialStore(store, hostControllerConfig.DataEncryptionKey)
	hc := controllers.NewHostController(hostStore, hostStatusStore, flavorStore,
		flavorGroupStore, hostCredentialStore, hostTrustManager, hostControllerConfig)
	esxiClusterController := controllers.NewESXiClusterController(esxiClusterStore, *hc)

	esxiClusterIdExpr := fmt.Sprintf("%s%s", "/esxi-cluster/", validation.IdReg)

	router.Handle("/esxi-cluster",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(esxiClusterController.Create),
			[]string{constants.ESXiClusterCreate}))).Methods(http.MethodPost)

	router.Handle("/esxi-cluster",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(esxiClusterController.Search),
			[]string{constants.ESXiClusterSearch}))).Methods(http.MethodGet)

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(PermissionsHandler(ResponseHandler(esxiClusterController.Delete),
			[]string{constants.ESXiClusterDelete}))).Methods(http.MethodDelete)

	router.Handle(esxiClusterIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(esxiClusterController.Retrieve),
			[]string{constants.ESXiClusterRetrieve}))).Methods(http.MethodGet)

	return router
}
