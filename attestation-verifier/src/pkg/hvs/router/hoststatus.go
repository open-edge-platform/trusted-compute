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
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
)

// SetHostStatusRoutes registers routes for host-status APIs
func SetHostStatusRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/hoststatus:SetHostStatusRoutes() Entering")
	defer defaultLog.Trace("router/hoststatus:SetHostStatusRoutes() Leaving")

	hoststatusStore := postgres.NewHostStatusStore(store)
	hoststatusController := controllers.HostStatusController{Store: hoststatusStore}

	router.Handle("/host-status", ErrorHandler(PermissionsHandler(JsonResponseHandler(hoststatusController.Search),
		[]string{constants.HostStatusSearch}))).Methods(http.MethodGet)

	hostStatusIdExpr := fmt.Sprintf("%s%s", "/host-status/", validation.IdReg)
	router.Handle(hostStatusIdExpr, ErrorHandler(PermissionsHandler(JsonResponseHandler(hoststatusController.Retrieve),
		[]string{constants.HostStatusRetrieve}))).Methods(http.MethodGet)

	return router
}
