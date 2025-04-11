/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package router

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"net/http"
)

// SetTpmEndorsementRoutes registers routes for tpm-endorsements
func SetTpmEndorsementRoutes(router *mux.Router, store *postgres.DataStore) *mux.Router {
	defaultLog.Trace("router/flavorgroups:SetTpmEndorsementRoutes() Entering")
	defer defaultLog.Trace("router/flavorgroups:SetTpmEndorsementRoutes() Leaving")

	tpmEndorsementStore := postgres.NewTpmEndorsementStore(store)
	tpmEndorsementController := controllers.TpmEndorsementController{Store: tpmEndorsementStore}
	tpmEndorsementIdExpr := fmt.Sprintf("%s%s", "/tpm-endorsements/", validation.IdReg)

	router.Handle("/tpm-endorsements",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(tpmEndorsementController.Create),
			[]string{constants.TpmEndorsementCreate}))).Methods(http.MethodPost)

	router.Handle(tpmEndorsementIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(tpmEndorsementController.Update),
			[]string{constants.TpmEndorsementStore}))).Methods(http.MethodPut)

	router.Handle("/tpm-endorsements",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(tpmEndorsementController.Search),
			[]string{constants.TpmEndorsementSearch}))).Methods(http.MethodGet)

	router.Handle(tpmEndorsementIdExpr,
		ErrorHandler(PermissionsHandler(ResponseHandler(tpmEndorsementController.Delete),
			[]string{constants.TpmEndorsementDelete}))).Methods(http.MethodDelete)

	router.Handle("/tpm-endorsements",
		ErrorHandler(PermissionsHandler(ResponseHandler(tpmEndorsementController.DeleteCollection),
			[]string{constants.TpmEndorsementSearch, constants.TpmEndorsementDelete}))).Methods(http.MethodDelete)

	router.Handle(tpmEndorsementIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(tpmEndorsementController.Retrieve),
			[]string{constants.TpmEndorsementRetrieve}))).Methods(http.MethodGet)

	return router
}
