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
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
)

// SetReportRoutes registers routes for reports
func SetReportRoutes(router *mux.Router, store *postgres.DataStore, hostTrustManager domain.HostTrustManager) *mux.Router {
	defaultLog.Trace("router/reports:SetReportRoutes() Entering")
	defer defaultLog.Trace("router/reports:SetReportRoutes() Leaving")

	reportStore := postgres.NewReportStore(store)
	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)
	reportController := controllers.NewReportController(reportStore, hostStore, hostStatusStore, hostTrustManager)

	reportIdExpr := fmt.Sprintf("%s%s", "/reports/", validation.IdReg)

	router.Handle("/reports",
		ErrorHandler(PermissionsHandler(ResponseHandler(reportController.CreateSaml),
			[]string{constants.ReportCreate}))).Methods(http.MethodPost).Headers("Accept", consts.HTTPMediaTypeSaml)

	router.Handle("/reports",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(reportController.Create),
			[]string{constants.ReportCreate}))).Methods(http.MethodPost)

	router.Handle("/reports",
		ErrorHandler(PermissionsHandler(ResponseHandler(reportController.SearchSaml),
			[]string{constants.ReportSearch}))).Methods(http.MethodGet).Headers("Accept", consts.HTTPMediaTypeSaml)

	router.Handle(reportIdExpr,
		ErrorHandler(PermissionsHandler(JsonResponseHandler(reportController.Retrieve),
			[]string{constants.ReportRetrieve}))).Methods(http.MethodGet)

	router.Handle("/reports",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(reportController.Search),
			[]string{constants.ReportSearch}))).Methods(http.MethodGet)

	return router
}
