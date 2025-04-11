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
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/controllers"
	aasRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	accountSeedFile      = "../../../test/aas/account-seed.txt"
	emptyAccountSeedFile = "../../../test/aas/empty-accountSeed.txt"
)

var _ = Describe("CredentialsController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	var credentialController controllers.CredentialsController

	// AccountSeedFile with no content provided.
	credentialControllerTest := controllers.CredentialsController{
		UserCredentialValidity: 60,
		AccountSeedFile:        emptyAccountSeedFile,
	}
	// Invalid AccountSeedFile path provided.
	credentialControllerInvalid := controllers.CredentialsController{
		UserCredentialValidity: 60,
		AccountSeedFile:        "../../../test/aas/empty-accountSeed1.txt",
	}

	BeforeEach(func() {
		router = mux.NewRouter()
		// Valid AccountSeedFile path provided.
		credentialController = controllers.CredentialsController{
			UserCredentialValidity: 60,
			AccountSeedFile:        accountSeedFile,
		}
	})

	Describe("CreateCredentials", func() {
		Context("Create request with unauhtorized", func() {
			It("Should return StatusUnauthorized - Invalid not create a valid Credentials", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "TA",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		Context("Validated Create request with Insufficient privileges", func() {
			It("Should return Unauthorized - Insufficient privilege", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "TA",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreatorRoleName},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		// Valid case Should create credentials TA
		Context("Validate Create request", func() {
			It("Should return StatusCreated - Valid request should create credentials", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "TA",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=TA",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		// Valid case Should create credentials HVS
		Context("Validate Create request", func() {
			It("Should return StatusCreated - Valid request for HVS type, should create credentials", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "HVS",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		// Validate Create request with empty AccountSeedFile file
		Context("Validate Create request with empty AccountSeedFile file", func() {
			It("Should return StatusBadRequest - Empty AccountSeedFile file given", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialControllerTest.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
										"type": "HVS",
										"parameters": {
											"host-id": "samplehostID"
										}
									}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Validate Create request with Invalid AccountSeedFile file
		Context("Validate Create request with Invalid AccountSeedFile file", func() {
			It("Should return StatusBadRequest - Invalid AccountSeedFile file given", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialControllerInvalid.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
											"type": "HVS",
											"parameters": {
												"host-id": "samplehostID"
											}
										}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Invalid component type
		Context("Validate Create request with invalid component type", func() {
			It("Should return StatusBadRequest - Invalid component type", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "InvalidComponentype",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=InvalidComponentype",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Validate with invalid roles
		Context("Validate Create request with invalid roles", func() {
			It("Should return Request Unauthorized - Empty roles provided", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "TA",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})
		})
		// Invalid content type
		Context("Validate Create request with Invalid content type", func() {
			It("Should return StatusUnsupportedMediaType - invalid content type", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "InvalidComponentype",
								"parameters": {
									"host-id": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		// Invalid content length
		Context("Validate Create request with Invalid content length", func() {
			It("Should return StatusBadRequest - Invalid content length", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					nil,
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Empty roles
		Context("Validate Create request with empty roles", func() {
			It("Should return StatusBadRequest - Empty roles given", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type_test": "HVS",
								"parameters_test": {
									"host-id_test": "samplehostID"
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Validate Create request with empty hostID", func() {
			It("Should return StatusCreated - Valid request should create credentials", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "HVS",
								"parameters": {
									"host-id": ""
								}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		// Invalid parameters
		Context("Validate Create request with empty parameters", func() {
			It("Should return StatusBadRequest - Empty paramters given in request", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
								"type": "TA",
								"parameters": {}
							}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		// Invalid HOSTID
		Context("Validate Create request with Invalid HOSTID", func() {
			It("Should return StatusBadRequest - Invalid HOST ID given", func() {
				router.Handle("/credentials", aasRoutes.ErrorHandler(aasRoutes.PermissionsHandler(
					aasRoutes.ResponseHandler(credentialController.CreateCredentials, "application/json"), []string{constants.CredentialCreate}))).Methods(http.MethodPost)
				credJson := `{
									"type": "TA",
									"parameters": {
										"host-id": SW50ZWyuIFNlY3VyaXR5IExpYnJhcmllcyBmb3IgRGF0YSBDZW50ZXIgKEludGVsriBTZWNMLURDKSBlbmFibGVzIHNlY3VyaXR5IHVzZSBjYXNlcyBmb3IgZGF0YSBjZW50ZXIgdXNpbmcgSW50ZWyuIGhhcmR3YXJlIHNlY3VyaXR5IHRlY2hub2xvZ2llcy4KCkhhcmR3YXJl
									}
								}`
				req, err := http.NewRequest(
					http.MethodPost,
					"/credentials",
					strings.NewReader(credJson),
				)

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.CredentialCreate},
				}
				req = context.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				val := []aas.RoleInfo{
					{
						Service: "AAS",
						Name:    "CredentialCreator",
						Context: "type=HVS",
					},
				}
				req = context.SetUserRoles(req, val)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
