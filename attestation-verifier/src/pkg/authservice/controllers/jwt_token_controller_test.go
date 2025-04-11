/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	comm "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres/mock"
	aasRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("JwtTokenController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var jwtController controllers.JwtTokenController
	// mock database
	mockDatabase := &mock.MockDatabase{
		MockUserStore:       getMockUserStore(),
		MockRoleStore:       getMockRoleStore(),
		MockPermissionStore: getPermissionStore(),
	}
	comm.InitDefender(5, 5, 15)

	BeforeEach(func() {
		router = mux.NewRouter()
		jwtController = controllers.JwtTokenController{
			Database:     mockDatabase,
			TokenFactory: tokenFactory,
		}
	})

	Describe("CreateJwtToken", func() {
		// Empty username and password
		Context("Validate CreateJwtToken with empty request", func() {
			It("Should return StatusBadRequest - Empty requet body provided", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/token", nil)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// Invalid user name and password
		Context("Validate CreateJwtToken with invalid username and password", func() {
			It("Should return StatusUnauthorized - Invalid username and password provided", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)

				usercred := `{
					"username":"testusername",
					"password":"testpassword"
					}`

				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		// Valid username and password
		Context("Validate CreateJwtToken with valid username and password", func() {
			It("Should return StatusOK - Valid request should create JwtToken", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)

				usercred := `{
					"username":"testusername",
					"password":"testAdminPassword"
					}`

				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		// Invalid username
		Context("Validate CreateJwtToken with Invalid username", func() {
			It("Should return StatusBadRequest - Invalid username provided", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)
				usercred := `{
					"username":1234567890,
					"password":"testAdminPassword"
					}`
				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Invalid username
		Context("Validate CreateJwtToken with max length username request", func() {
			It("Should return StatusUnauthorized - Invalid username provided", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)
				usercred := `{
							"username":"ARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZo",
							"password":"testAdminPassword"
							}`
				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		// Invalid password
		Context("Validate CreateJwtToken with invalid max length password request", func() {
			It("Should return StatusUnauthorized - Invalid password provided", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)
				usercred := `{
									"username":"testusername",
									"password":"ARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZo"
									}`
				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})

		// To validate GetRoles() in CreateJwtToken(), Simulated to return postgres error
		Context("Validate CreateJwtToken with invalid role validation", func() {
			It("Should return StatusInternalServerError - Failed to get role(s)", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)

				usercred := `{
					"username":"testusername2",
					"password":"testAdminPassword"
					}`

				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
		// To validate GetPermissions() in CreateJwtToken(), Simulated to return postgres error
		Context("Validate CreateJwtToken with invalid permission", func() {
			It("Should return StatusInternalServerError - Failed to get permission(s)", func() {
				router.Handle("/token", aasRoutes.ErrorHandler(aasRoutes.ResponseHandler(jwtController.CreateJwtToken, "application/jwt"))).Methods(http.MethodPost)

				usercred := `{
					"username":"testusername3",
					"password":"testAdminPassword"
					}`

				req, err := http.NewRequest(http.MethodPost, "/token", strings.NewReader(usercred))

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
		// To validate CreateCustomClaimsJwtToken with empty request
		Context("Validate CreateCustomClaimsJwtToken with empty request", func() {
			It("Should return StatusBadRequest - Empty request provided", func() {
				router.Handle("/custom-claims-token", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(jwtController.CreateCustomClaimsJwtToken, "application/jwt"),
					[]string{constants.CustomClaimsCreate}))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/custom-claims-token", nil)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CustomClaimsCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// To validate CreateCustomClaimsJwtToken with Invalid request body
		Context("Validate CreateCustomClaimsJwtToken with invalid request body", func() {
			It("Should return StatusBadRequest - Invalid request body provided", func() {
				router.Handle("/custom-claims-token", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(jwtController.CreateCustomClaimsJwtToken, "application/jwt"), []string{constants.CustomClaimsCreate}))).Methods(http.MethodPost)

				usercred := `{
							"username":"testusername3",
							"password":"testAdminPassword"
							}`

				req, err := http.NewRequest(http.MethodPost, "/custom-claims-token", strings.NewReader(usercred))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CustomClaimsCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		// To validate CreateCustomClaimsJwtToken with valid request
		Context("Validate CreateCustomClaimsJwtToken with valid request", func() {
			It("Should return StatusOK -  Valid request should create CustomClaimsJwtToken", func() {
				router.Handle("/custom-claims-token", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(jwtController.CreateCustomClaimsJwtToken, "application/jwt"), []string{constants.CustomClaimsCreate}))).Methods(http.MethodPost)

				usercred := `{
								"subject": "test_user",
								"validity_seconds": 31536000,
								"claims": {
									"permissions": [
										{
											"service": "KBS",
											"context": "USA"
										}
									]
								}
							}`

				req, err := http.NewRequest(http.MethodPost, "/custom-claims-token", strings.NewReader(usercred))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CustomClaimsCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Validate CreateCustomClaimsJwtToken with invalid request", func() {
			It("Should return StatusBadRequest - Invalid subject provided", func() {
				router.Handle("/custom-claims-token", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(jwtController.CreateCustomClaimsJwtToken, "application/jwt"), []string{constants.CustomClaimsCreate}))).Methods(http.MethodPost)

				usercred := `{
										"subject": "ARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsARIIHq2xUtPhAEnwf4ldJPJF4kmp41P8R8T6Gy7UmVYf0dEtIDkPCi9FGI8wuwyGvKSqZo",
										"validity_seconds": 31536000,
										"claims": {
											"permissions": [
												{
													"service": "KBS",
													"context": "USA"
												}
											]
										}
									}`

				req, err := http.NewRequest(http.MethodPost, "/custom-claims-token", strings.NewReader(usercred))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CustomClaimsCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
