/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
)

//SetFlavorFromAppManifestRoute registers routes for APIs that return software flavor from manifest
func SetFlavorFromAppManifestRoute(router *mux.Router, store *postgres.DataStore, flavorGroupStore domain.FlavorGroupStore, certStore *crypt.CertificatesStore,
	hostTrustManager domain.HostTrustManager, hcConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/flavor-from-app-manifest:SetFlavorFromAppManifestRoute() Entering")
	defer defaultLog.Trace("router/flavor-from-app-manifest:SetFlavorFromAppManifestRoute() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	hostStore := postgres.NewHostStore(store)
	tagCertStore := postgres.NewTagCertificateStore(store)
	flavorTemplateStore := postgres.NewFlavorTemplateStore(store)
	flavorController := controllers.NewFlavorController(flavorStore, flavorGroupStore, hostStore, tagCertStore, hostTrustManager, certStore, hcConfig, flavorTemplateStore)
	flavorFromAppManifestController := controllers.NewFlavorFromAppManifestController(*flavorController)

	router.Handle("/flavor-from-app-manifest",
		ErrorHandler(PermissionsHandler(JsonResponseHandler(flavorFromAppManifestController.CreateSoftwareFlavor),
			[]string{constants.SoftwareFlavorCreate}))).Methods(http.MethodPost)

	return router
}
