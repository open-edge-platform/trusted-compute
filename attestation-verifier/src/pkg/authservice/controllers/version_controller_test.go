/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	aasRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("VersionController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var versionController controllers.VersionController

	BeforeEach(func() {
		router = mux.NewRouter()
		versionController = controllers.VersionController{}
	})

	Describe("GetVersion", func() {
		Context("GetVersion request", func() {
			It("Should GetVersion", func() {
				router.Handle("/version", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(versionController.GetVersion, ""))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/version", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})
})
