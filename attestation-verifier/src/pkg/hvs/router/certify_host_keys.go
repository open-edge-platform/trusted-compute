/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package router

import (
	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"net/http"
)

func SetCertifyHostKeysRoutes(router *mux.Router, certStore *crypt.CertificatesStore) *mux.Router {
	defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Entering")
	defer defaultLog.Trace("router/certify_host_keys:SetCertifyHostKeys() Leaving")

	certifyHostKeysController := controllers.NewCertifyHostKeysController(certStore)
	if certifyHostKeysController == nil {
		defaultLog.Error("router/certify_host_keys:SetCertifyHostKeys() Could not instantiate CertifyHostKeysController")
	}
	router.HandleFunc("/rpc/certify-host-signing-key", ErrorHandler(PermissionsHandler(JsonResponseHandler(certifyHostKeysController.CertifySigningKey), []string{consts.CertifyHostSigningKey}))).Methods(http.MethodPost)
	router.HandleFunc("/rpc/certify-host-binding-key", ErrorHandler(PermissionsHandler(JsonResponseHandler(certifyHostKeysController.CertifyBindingKey), []string{consts.CertifyHostSigningKey}))).Methods(http.MethodPost)
	return router
}

func SetCertifyAiksRoutes(router *mux.Router, store *postgres.DataStore, certStore *crypt.CertificatesStore, aikCertValidity int, enableEkCertRevokeChecks bool, requireEKCertForHostProvision bool) *mux.Router {
	defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Entering")
	defer defaultLog.Trace("router/certify_host_aiks:SetCertifyAiksRoutes() Leaving")

	tpmEndorsementStore := postgres.NewTpmEndorsementStore(store)
	certifyHostAiksController := controllers.NewCertifyHostAiksController(certStore, tpmEndorsementStore, aikCertValidity, consts.AikRequestsDir, enableEkCertRevokeChecks, requireEKCertForHostProvision)
	if certifyHostAiksController != nil {
		router.Handle("/privacyca/identity-challenge-request", ErrorHandler(PermissionsHandler(JsonResponseHandler(certifyHostAiksController.IdentityRequestGetChallenge),
			[]string{consts.CertifyAik}))).Methods(http.MethodPost)
		router.Handle("/privacyca/identity-challenge-response", ErrorHandler(PermissionsHandler(JsonResponseHandler(certifyHostAiksController.IdentityRequestSubmitChallengeResponse),
			[]string{consts.CertifyAik}))).Methods(http.MethodPost)
	}
	return router
}
