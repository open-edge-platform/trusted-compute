/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"net/http"
)

//SetDeploySoftwareManifestRoute registers routes for APIs that deploy software manifest to host
func SetDeploySoftwareManifestRoute(router *mux.Router, store *postgres.DataStore, htm domain.HostTrustManager,
	hcConfig domain.HostControllerConfig) *mux.Router {
	defaultLog.Trace("router/deploy_software_manifest:SetDeploySoftwareManifestRoute() Entering")
	defer defaultLog.Trace("router/deploy_software_manifest:SetDeploySoftwareManifestRoute() Leaving")

	flavorStore := postgres.NewFlavorStore(store)
	flavorGroupStore := postgres.NewFlavorGroupStore(store)
	hostStore := postgres.NewHostStore(store)
	hostStatusStore := postgres.NewHostStatusStore(store)

	hostCredentialStore := postgres.NewHostCredentialStore(store, hcConfig.DataEncryptionKey)
	hc := controllers.NewHostController(hostStore, hostStatusStore, flavorStore,
		flavorGroupStore, hostCredentialStore, htm, hcConfig)
	dsmController := controllers.NewDeploySoftwareManifestController(flavorStore, *hc)

	router.Handle("/rpc/deploy-software-manifest",
		ErrorHandler(PermissionsHandler(ResponseHandler(dsmController.DeployManifest),
			[]string{constants.SoftwareFlavorDeploy}))).Methods(http.MethodPost)

	return router
}
