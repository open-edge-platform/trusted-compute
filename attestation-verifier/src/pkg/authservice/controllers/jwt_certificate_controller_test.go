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

const (
	tokenSignCertFile = "../../../test/aas/jwtsigncert.pem"
)

var _ = Describe("JwtCertificateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var jwtCertificateController controllers.JwtCertificateController

	jwtCertificateControllerTest := controllers.JwtCertificateController{
		TokenSignCertFile: "../../../test/aas/jwtsigncert1.pem",
	}

	BeforeEach(func() {
		router = mux.NewRouter()
		jwtCertificateController = controllers.JwtCertificateController{
			TokenSignCertFile: tokenSignCertFile,
		}
	})

	Describe("GetJwtCertificate", func() {
		Context("Validate Get JwtCertificate", func() {
			It("Should return StatusOK - Valid certificate provided", func() {
				router.Handle("/jwt-certificates", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtCertificateController.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/jwt-certificates", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})

			It("Should return InternalServerError - Invalid certificate location provided", func() {
				router.Handle("/jwt-certificates", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtCertificateControllerTest.GetJwtCertificate, "application/x-pem-file"))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/jwt-certificates", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})
})
