/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	smocks "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	comctx "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var flavorController *controllers.FlavorController
	var hostStore *mocks.MockHostStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var flavorTemplateStore *mocks.MockFlavorTemplateStore
	var hostTrustManager *smocks.MockHostTrustManager
	var hostStatusStore *mocks.MockHostStatusStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController controllers.HostController
	var hostControllerConfig domain.HostControllerConfig
	var hostConnectorProvider mocks2.MockHostConnectorFactory

	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		flavorStore = mocks.NewMockFlavorStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		flavorTemplateStore = mocks.NewFakeFlavorTemplateStore()
		certStore := mocks.NewFakeCertificatesStore()
		tagCertStore := mocks.NewMockTagCertificateStore()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()

		// init hostControllerConfig
		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, _ := base64.StdEncoding.DecodeString(dekBase64)
		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     dek,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}

		hostController = controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}

		flavorController = &controllers.FlavorController{
			FStore:    flavorStore,
			FGStore:   flavorGroupStore,
			HStore:    hostStore,
			CertStore: certStore,
			TCStore:   tagCertStore,
			HTManager: hostTrustManager,
			HostCon:   hostController,
			FTStore:   flavorTemplateStore,
		}
	})
	// Specs for HTTP Get to "/flavors"
	Describe("Search Flavors", func() {
		Context("When no filter arguments are passed", func() {
			It("All Flavors records are returned", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).ToNot(HaveOccurred())
				//TODO Requires changes in mock flavor search method for this criteria
				Expect(len(sfs.SignedFlavors)).To(Equal(0))
			})
		})

		Context("When limit arguments are passed", func() {
			It("only 1 record is returned", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?limit=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(sfs.SignedFlavors)).To(Equal(1))
			})
		})
		Context("When afterid arguments are passed", func() {
			It("only records after afterid 1 are returned", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?afterId=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(sfs.SignedFlavors)).To(Equal(1))
			})
		})
		Context("When invalid limit is passed", func() {
			It("Should return bad request", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?limit=-4", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When invalid afterid is passed", func() {
			It("Should return bad request", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?afterId=-aaa", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When filtered by Flavor id", func() {
			It("Should get a single flavor entry", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?id=c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(sfs.SignedFlavors)).To(Equal(1))
			})
		})
		Context("When filtered by Flavor meta description key-value pair", func() {
			It("Should get a single flavor entry", func() {
				router.Handle("/flavors", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors?key=bios_name&&value=Intel Corporation", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var sfs *hvs.SignedFlavorCollection
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).NotTo(HaveOccurred())
				//TODO Requires changes in mock flavor search method for this criteria
				Expect(len(sfs.SignedFlavors)).To(Equal(0))
			})
		})
	})

	// Specs for HTTP Get to "/flavors/{flavor_id}"
	Describe("Retrieve Flavor", func() {
		Context("Retrieve Flavor by valid ID from data store", func() {
			It("Should retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Flavor(created by template) by valid ID from data store", func() {
			It("Should retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors/e6612219-bbd5-4259-8c7e-991e43729a86", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Try to retrieve Flavor by non-existent ID from data store", func() {
			It("Should fail to retrieve Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/flavors/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))

				var sfs []*hvs.SignedFlavor
				err = json.Unmarshal(w.Body.Bytes(), &sfs)
				Expect(err).To(HaveOccurred())
				Expect(sfs).To(BeNil())
			})
		})
	})

	// Specs for HTTP Delete to "/flavors/{flavorId}"
	Describe("Delete Flavor by ID", func() {
		Context("Delete Flavor by ID from data store", func() {
			It("Should delete Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/flavors/c36b5412-8c02-4e08-8a74-8bfa40425cf3", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete Flavor by invalid ID from data store", func() {
			It("Should fail to delete Flavor", func() {
				router.Handle("/flavors/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(flavorController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/flavors/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Post to "/flavor"
	Describe("Create a new flavor", func() {
		Context("Provide a invalid Create request with XSS Attack Strings", func() {
			It("Should return 400 response code", func() {
				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
								"connection_string": "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//–>\">'>",
								"tls_policy_id": "TRUST_FIRST_CERTIFICATE",
								"flavorgroup_name": "",
								"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","SOFTWARE","IMA"]
							}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))

				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a Create request without Accept header", func() {
			It("Should return 415 response code", func() {
				flavorJson := `{
									"connection_string": "intel:https://another.ta.ip.com:1443",
									"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","SOFTWARE","IMA"]
								}`
				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a Create request without Content-Type header", func() {
			It("Should return 415 response code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
									"connection_string": "intel:https://another.ta.ip.com:1443",
									"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","SOFTWARE","IMA"]
								}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})

				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a empty create request", func() {
			It("Should return 415 response code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/flavors", nil)
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a connection string flavor create request", func() {
			It("Should return 201 response code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","ASSET_TAG","IMA"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a empty connection string for flavor create request", func() {
			It("Should return 400 response code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "",
					"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","ASSET_TAG","IMA"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a invalid connection string for flavor create request", func() {
			It("Should return 400 response code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;u=admin()",
					"partial_flavor_types": ["PLATFORM","OS","HOST_UNIQUE","ASSET_TAG","IMA"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a flavor create request with Insufficient permissions for all flavors", func() {
			It("Should return 401 response code - Insufficient permissions given to create flavor PLATFORM", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": ["PLATFORM"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.SoftwareFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("Should return 401 response code - Insufficient permissions given to create flavor SOFTWARE", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": ["SOFTWARE"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.HostUniqueFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("Should return 401 response code - Insufficient permissions given to create flavor HOST_UNIQUE", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": ["HOST_UNIQUE"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.SoftwareFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("Should return 401 response code - Insufficient permissions given to create flavor ASSET_TAG", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": ["ASSET_TAG"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.SoftwareFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("Should return 401 response code - Empty flavor list given", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": []
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.SoftwareFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

			It("Should return 401 response code - Empty flavor list given with invalid permission", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorReq := `{
					"connection_string":  "https://127.0.0.1:1443;",
					"partial_flavor_types": [],
					"flavorgroup_names":["testFlavorGroup"]
				}`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorReq))
				Expect(err).NotTo(HaveOccurred())
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnauthorized))
			})

		})

		Context("Provide a valid manually crafted Flavor request", func() {
			It("Should return 201 Response code and a signed flavor", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
						"connection_string":"",
						"flavor_collection":{
						   "flavors":[
							  {
								 "flavor":{
									"meta":{
									   "id":"0fcb8e8d-6fe6-46ba-9526-32b53bf3df75",
									   "description":{
										  "bios_name":"Intel Corporation",
										  "bios_version":"SE5C610.86B.01.01.0016.033120161139",
										  "flavor_part":"PLATFORM",
										  "flavor_template_ids":[
											 "8b022050-3ade-40fd-8e3b-45bf8b1dc56a"
										  ],
										  "label":"INTEL_IntelCorporation_SE5C610.86B.01.01.0016.033120161139_TPM_TXT_2021-04-23T12:25:58.815135+05:30",
										  "source":"k8s-node",
										  "tboot_installed":true,
										  "tpm_version":"2.0"
									   },
									   "vendor":"INTEL"
									},
									"bios":{
									   "bios_name":"Intel Corporation",
									   "bios_version":"SE5C610.86B.01.01.0016.033120161139"
									},
									"hardware":{
									   "processor_info":"F1 06 04 00 FF FB EB BF",
									   "processor_flags":"FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
									   "feature":{
										  "TXT":{
											 "supported":"true",
											 "enabled":"true"
										  },
										  "TPM":{
											 "supported":"true",
											 "enabled":"true",
											 "meta":{
												"tpm_version":"2.0",
												"pcr_banks":[
												   "SHA1",
												   "SHA256"
												]
											 }
										  },
										  "CBNT":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"profile":"",
												"msr":""
											 }
										  },
										  "UEFI":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"secure_boot_enabled":false
											 }
										  },
										  "PFR":{
											 "supported":"false",
											 "enabled":"false"
										  },
										  "BMC":{
											 "supported":"false",
											 "enabled":"false"
										  }
									   }
									},
									"pcrs":[
									   {
										  "pcr":{
											 "index":0,
											 "bank":"SHA256"
										  },
										  "measurement":"fad7981e1d16de3269667f4e84bf84a0a0c84f4f8a183e13ac5ba1c441bbfd3c",
										  "pcr_matches":true
									   },
									   {
										  "pcr":{
											 "index":17,
											 "bank":"SHA256"
										  },
										  "measurement":"b33e4a30200d6bc8c4d5b439c682fd591afaa500e045de85cf945c75a6d27860",
										  "pcr_matches":true,
										  "eventlog_equals":{
											 "events":[
												{
												   "type_id":"0x402",
												   "type_name":"HASH_START",
												   "tags":[
													  "HASH_START"
												   ],
												   "measurement":"4bf4446b07c0cc0159f7df959c118887eefb3510983ce8eadbc7557af2e1f06f"
												},
												{
												   "type_id":"0x40a",
												   "type_name":"BIOSAC_REG_DATA",
												   "tags":[
													  "BIOSAC_REG_DATA"
												   ],
												   "measurement":"8eb9c8fd49f5c228ee42eb581b1d134ee6d30925d019717ca83d9041ec04ce13"
												},
												{
												   "type_id":"0x40b",
												   "type_name":"CPU_SCRTM_STAT",
												   "tags":[
													  "CPU_SCRTM_STAT"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x412",
												   "type_name":"LCP_DETAILS_HASH",
												   "tags":[
													  "LCP_DETAILS_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x40e",
												   "type_name":"STM_HASH",
												   "tags":[
													  "STM_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x40f",
												   "type_name":"OSSINITDATA_CAP_HASH",
												   "tags":[
													  "OSSINITDATA_CAP_HASH"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x404",
												   "type_name":"MLE_HASH",
												   "tags":[
													  "MLE_HASH"
												   ],
												   "measurement":"3b02dbc9b1669d14d5085184b9558f5ff8beb348770608d1eeff8437366773e0"
												},
												{
												   "type_id":"0x414",
												   "type_name":"NV_INFO_HASH",
												   "tags":[
													  "NV_INFO_HASH"
												   ],
												   "measurement":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
												},
												{
												   "type_id":"0x501",
												   "type_name":"tb_policy",
												   "tags":[
													  "tb_policy"
												   ],
												   "measurement":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67"
												}
											 ],
											 "exclude_tags":[
												"LCP_CONTROL_HASH",
												"initrd",
												"vmlinuz"
											 ]
										  }
									   },
									   {
										  "pcr":{
											 "index":18,
											 "bank":"SHA256"
										  },
										  "measurement":"6f33d58a1fc09382042d2fd650f4c26af20cf2b18ea3bc0fdb075af2fa04f6d9",
										  "pcr_matches":true,
										  "eventlog_equals":{
											 "events":[
												{
												   "type_id":"0x410",
												   "type_name":"SINIT_PUBKEY_HASH",
												   "tags":[
													  "SINIT_PUBKEY_HASH"
												   ],
												   "measurement":"dbd2dc6c323d51b61aea2706133b587fea2ef2fa70b5a523b8138e9154302e20"
												},
												{
												   "type_id":"0x40b",
												   "type_name":"CPU_SCRTM_STAT",
												   "tags":[
													  "CPU_SCRTM_STAT"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x40f",
												   "type_name":"OSSINITDATA_CAP_HASH",
												   "tags":[
													  "OSSINITDATA_CAP_HASH"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x413",
												   "type_name":"LCP_AUTHORITIES_HASH",
												   "tags":[
													  "LCP_AUTHORITIES_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x414",
												   "type_name":"NV_INFO_HASH",
												   "tags":[
													  "NV_INFO_HASH"
												   ],
												   "measurement":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
												},
												{
												   "type_id":"0x501",
												   "type_name":"tb_policy",
												   "tags":[
													  "tb_policy"
												   ],
												   "measurement":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67"
												}
											 ],
											 "exclude_tags":[
												"LCP_CONTROL_HASH",
												"initrd",
												"vmlinuz"
											 ]
										  }
									   }
									]
								 },
								 "signature":"ppfkmzhhBMTcVRAztNK1qp/9Ioh8krIgcvIhvIi1xaAxh/4hKSKc4mwKqSIlYpFO64hu9qzv6j6Ap9cw5gM4ZDu3oJkli9pJ/2+9y/9XIYs7nw+sV/i1xNdgzeUbw7urvARf8PmS6/AxltNNdPslrfpPvWHtnIU8yVpwoMTCbThK9JL8ZIZQLXouTJ1Cdh2YMSfsQa8840yFoKPFMz0n2mn70lGKbaWY3wyET5KWJFMLGxTpVkkWoO5Eh+K+2g6h+R/gBo1j+GQDcG4MZ/9dtHAu0iGrFxTSJ7LtSQtlzXUH+aYUE03jmF1Hdhwdhe5WZ4PEyNCIef31ewhSwY3Xp5xlmZdqOLS7bZGdC7FomtDgiRLAzC8wEu4BVSBZqtqwg/Unf2dnqKRFVk5dayM2pc8XFRLKOzBu2FUmah4/SoXC6u1xGMpZzbkL7CWQK1JHJBvLymiQoEkxEOknzXi5hJYAtc1q21lmINPl5VPLWPGF6JWlnhxCG4XcMe9jSNIY"
							  }
						   ]
						},
						"flavorgroup_names":[
						   "Test"
						],
						"partial_flavor_types":[
						   "PLATFORM"
						]
					 }`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
			})
		})

		Context("Provide a invalid manually crafted Flavor request", func() {
			It("Should return status bad request request code since flavor group is not found", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
						"connection_string":"",
						"flavor_collection":{
						   "flavors":[
							  {
								 "flavor":{
									"meta":{
									   "id":"0fcb8e8d-6fe6-46ba-9526-32b53bf3df75",
									   "description":{},
									   "vendor":"INTEL"
									},
									"bios":{
									   "bios_name":"Intel Corporation",
									   "bios_version":"SE5C610.86B.01.01.0016.033120161139"
									},
									"hardware":{
									   "processor_info":"F1 06 04 00 FF FB EB BF",
									   "processor_flags":"FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
									   "feature":{
										  "TXT":{
											 "supported":"true",
											 "enabled":"true"
										  },
										  "TPM":{
											 "supported":"true",
											 "enabled":"true",
											 "meta":{
												"tpm_version":"2.0",
												"pcr_banks":[
												   "SHA1",
												   "SHA256"
												]
											 }
										  },
										  "CBNT":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"profile":"",
												"msr":""
											 }
										  },
										  "UEFI":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"secure_boot_enabled":false
											 }
										  },
										  "PFR":{
											 "supported":"false",
											 "enabled":"false"
										  },
										  "BMC":{
											 "supported":"false",
											 "enabled":"false"
										  }
									   }
									},
									"pcrs":[
									   {
										  "pcr":{
											 "index":0,
											 "bank":"SHA256"
										  },
										  "measurement":"fad7981e1d16de3269667f4e84bf84a0a0c84f4f8a183e13ac5ba1c441bbfd3c",
										  "pcr_matches":true
									   }
									]
								 },
								 "signature":"ppfkmzhhBMTcVRAztNK1qp/9Ioh8krIgcvIhvIi1xaAxh/4hKSKc4mwKqSIlYpFO64hu9qzv6j6Ap9cw5gM4ZDu3oJkli9pJ/2+9y/9XIYs7nw+sV/i1xNdgzeUbw7urvARf8PmS6/AxltNNdPslrfpPvWHtnIU8yVpwoMTCbThK9JL8ZIZQLXouTJ1Cdh2YMSfsQa8840yFoKPFMz0n2mn70lGKbaWY3wyET5KWJFMLGxTpVkkWoO5Eh+K+2g6h+R/gBo1j+GQDcG4MZ/9dtHAu0iGrFxTSJ7LtSQtlzXUH+aYUE03jmF1Hdhwdhe5WZ4PEyNCIef31ewhSwY3Xp5xlmZdqOLS7bZGdC7FomtDgiRLAzC8wEu4BVSBZqtqwg/Unf2dnqKRFVk5dayM2pc8XFRLKOzBu2FUmah4/SoXC6u1xGMpZzbkL7CWQK1JHJBvLymiQoEkxEOknzXi5hJYAtc1q21lmINPl5VPLWPGF6JWlnhxCG4XcMe9jSNIY"
							  }
						   ]
						},
						"flavorgroup_names":[
						   "Test"
						],
						"partial_flavor_types":[
						   "PLATFORM"
						]
					 }`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a invalid manually crafted Flavor request", func() {
			It("Should return 500 Response code since description is empty", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
						"connection_string":"",
						"flavor_collection":{
						   "flavors":[
							  {
								 "flavor":{
									"meta":{
									   "id":"0fcb8e8d-6fe6-46ba-9526-32b53bf3df75",
									   "description":{},
									   "vendor":"INTEL"
									},
									"bios":{
									   "bios_name":"Intel Corporation",
									   "bios_version":"SE5C610.86B.01.01.0016.033120161139"
									},
									"hardware":{
									   "processor_info":"F1 06 04 00 FF FB EB BF",
									   "processor_flags":"FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
									   "feature":{
										  "TXT":{
											 "supported":"true",
											 "enabled":"true"
										  },
										  "TPM":{
											 "supported":"true",
											 "enabled":"true",
											 "meta":{
												"tpm_version":"2.0",
												"pcr_banks":[
												   "SHA1",
												   "SHA256"
												]
											 }
										  },
										  "CBNT":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"profile":"",
												"msr":""
											 }
										  },
										  "UEFI":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"secure_boot_enabled":false
											 }
										  },
										  "PFR":{
											 "supported":"false",
											 "enabled":"false"
										  },
										  "BMC":{
											 "supported":"false",
											 "enabled":"false"
										  }
									   }
									},
									"pcrs":[
									   {
										  "pcr":{
											 "index":0,
											 "bank":"SHA256"
										  },
										  "measurement":"fad7981e1d16de3269667f4e84bf84a0a0c84f4f8a183e13ac5ba1c441bbfd3c",
										  "pcr_matches":true
									   }
									]
								 },
								 "signature":"ppfkmzhhBMTcVRAztNK1qp/9Ioh8krIgcvIhvIi1xaAxh/4hKSKc4mwKqSIlYpFO64hu9qzv6j6Ap9cw5gM4ZDu3oJkli9pJ/2+9y/9XIYs7nw+sV/i1xNdgzeUbw7urvARf8PmS6/AxltNNdPslrfpPvWHtnIU8yVpwoMTCbThK9JL8ZIZQLXouTJ1Cdh2YMSfsQa8840yFoKPFMz0n2mn70lGKbaWY3wyET5KWJFMLGxTpVkkWoO5Eh+K+2g6h+R/gBo1j+GQDcG4MZ/9dtHAu0iGrFxTSJ7LtSQtlzXUH+aYUE03jmF1Hdhwdhe5WZ4PEyNCIef31ewhSwY3Xp5xlmZdqOLS7bZGdC7FomtDgiRLAzC8wEu4BVSBZqtqwg/Unf2dnqKRFVk5dayM2pc8XFRLKOzBu2FUmah4/SoXC6u1xGMpZzbkL7CWQK1JHJBvLymiQoEkxEOknzXi5hJYAtc1q21lmINPl5VPLWPGF6JWlnhxCG4XcMe9jSNIY"
							  }
						   ]
						},
						"partial_flavor_types":[
						   "PLATFORM"
						]
					 }`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Provide a manually crafted Flavor request with an invalid field name", func() {
			It("Should return 400 Error code", func() {

				router.Handle("/flavors",
					hvsRoutes.ErrorHandler(hvsRoutes.PermissionsHandler(hvsRoutes.JsonResponseHandler(flavorController.Create),
						[]string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate}))).
					Methods(http.MethodPost)

				flavorJson := `{
						"connection_string":"",
						"flavor_collection":{
						   "flavors":[
							  {
								 "flavor":{
									"meta":{
									   "id":"0fcb8e8d-6fe6-46ba-9526-32b53bf3df7b",
									   "description":{
										  "bios_name":"Intel Corporation",
										  "bios_version":"SE5C610.86B.01.01.0016.033120161139",
										  "flavor_part":"PLATFORM",
										  "flavor_template_ids":[
											 "8b022050-3ade-40fd-8e3b-45bf8b1dc56a"
										  ],
										  "label":"INTEL_IntelCorporation_SE5C610.86B.01.01.0016.033120161139_TPM_TXT_2021-04-23T12:25:58.815135+05:30",
										  "source":"k8s-node",
										  "tboot_installed":true,
										  "tpm_version":"2.0"
									   },
									   "vendor":"INTEL"
									},
									"bios":{
									   "bios_name":"Intel Corporation",
									   "bios_version":"SE5C610.86B.01.01.0016.033120161139"
									},
									"hardware":{
									   "processor_info":"F1 06 04 00 FF FB EB BF",
									   "processor_flags":"FPU VME DE PSE TSC MSR PAE MCE CX8 APIC SEP MTRR PGE MCA CMOV PAT PSE-36 CLFSH DS ACPI MMX FXSR SSE SSE2 SS HTT TM PBE",
									   "feature":{
										  "TXT":{
											 "supported":"true",
											 "enabled":"true"
										  },
										  "TPM":{
											 "supported":"true",
											 "enabled":"true",
											 "meta":{
												"tpm_version":"2.0",
												"pcr_banks":[
												   "SHA1",
												   "SHA256"
												]
											 }
										  },
										  "CBNT":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"profile":"",
												"msr":""
											 }
										  },
										  "UEFI":{
											 "supported":"false",
											 "enabled":"false",
											 "meta":{
												"secure_boot_enabled":false
											 }
										  },
										  "PFR":{
											 "supported":"false",
											 "enabled":"false"
										  },
										  "BMC":{
											 "supported":"false",
											 "enabled":"false"
										  }
									   }
									},
									"pcrs":[
									   {
										  "pcr":{
											 "index":0,
											 "bank":"SHA256"
										  },
										  "measurement":"fad7981e1d16de3269667f4e84bf84a0a0c84f4f8a183e13ac5ba1c441bbfd3c",
										  "pcr_matches":true
									   },
									   {
										  "pcr":{
											 "index":17,
											 "bank":"SHA256"
										  },
										  "measurement":"b33e4a30200d6bc8c4d5b439c682fd591afaa500e045de85cf945c75a6d27860",
										  "pcr_matches":true,
										  "eventlog_equals":{
											 "events":[
												{
												   "type_id":"0x402",
												   "type_name":"HASH_START",
												   "tags":[
													  "HASH_START"
												   ],
												   "measurement":"4bf4446b07c0cc0159f7df959c118887eefb3510983ce8eadbc7557af2e1f06f"
												},
												{
												   "type_id":"0x40a",
												   "type_name":"BIOSAC_REG_DATA",
												   "tags":[
													  "BIOSAC_REG_DATA"
												   ],
												   "measurement":"8eb9c8fd49f5c228ee42eb581b1d134ee6d30925d019717ca83d9041ec04ce13"
												},
												{
												   "type_id":"0x40b",
												   "type_name":"CPU_SCRTM_STAT",
												   "tags":[
													  "CPU_SCRTM_STAT"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x412",
												   "type_name":"LCP_DETAILS_HASH",
												   "tags":[
													  "LCP_DETAILS_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x40e",
												   "type_name":"STM_HASH",
												   "tags":[
													  "STM_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x40f",
												   "type_name":"OSSINITDATA_CAP_HASH",
												   "tags":[
													  "OSSINITDATA_CAP_HASH"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x404",
												   "type_name":"MLE_HASH",
												   "tags":[
													  "MLE_HASH"
												   ],
												   "measurement":"3b02dbc9b1669d14d5085184b9558f5ff8beb348770608d1eeff8437366773e0"
												},
												{
												   "type_id":"0x414",
												   "type_name":"NV_INFO_HASH",
												   "tags":[
													  "NV_INFO_HASH"
												   ],
												   "measurement":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
												},
												{
												   "type_id":"0x501",
												   "type_name":"tb_policy",
												   "tags":[
													  "tb_policy"
												   ],
												   "measurement":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67"
												}
											 ],
											 "exclude_tags":[
												"LCP_CONTROL_HASH",
												"initrd",
												"vmlinuz"
											 ]
										  }
									   },
									   {
										  "pcr":{
											 "index":18,
											 "bank":"SHA256"
										  },
										  "measurement":"6f33d58a1fc09382042d2fd650f4c26af20cf2b18ea3bc0fdb075af2fa04f6d9",
										  "pcr_matches":true,
										  "eventlog_equals":{
											 "events":[
												{
												   "type_id":"0x410",
												   "type_name":"SINIT_PUBKEY_HASH",
												   "tags":[
													  "SINIT_PUBKEY_HASH"
												   ],
												   "measurement":"dbd2dc6c323d51b61aea2706133b587fea2ef2fa70b5a523b8138e9154302e20"
												},
												{
												   "type_id":"0x40b",
												   "type_name":"CPU_SCRTM_STAT",
												   "tags":[
													  "CPU_SCRTM_STAT"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x40f",
												   "type_name":"OSSINITDATA_CAP_HASH",
												   "tags":[
													  "OSSINITDATA_CAP_HASH"
												   ],
												   "measurement":"67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450"
												},
												{
												   "type_id":"0x413",
												   "type_name":"LCP_AUTHORITIES_HASH",
												   "tags":[
													  "LCP_AUTHORITIES_HASH"
												   ],
												   "measurement":"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
												},
												{
												   "type_id":"0x414",
												   "type_name":"NV_INFO_HASH",
												   "tags":[
													  "NV_INFO_HASH"
												   ],
												   "measurement":"0f6e0c7a5944963d7081ea494ddff1e9afa689e148e39f684db06578869ea38b"
												},
												{
												   "type_id":"0x501",
												   "type_name":"tb_policy",
												   "tags":[
													  "tb_policy"
												   ],
												   "measurement":"27808f64e6383982cd3bcc10cfcb3457c0b65f465f779d89b668839eaf263a67"
												}
											 ],
											 "exclude_tags":[
												"LCP_CONTROL_HASH",
												"initrd",
												"vmlinuz"
											 ]
										  }
									   }
									]
								 },
								 "signature":"ppfkmzhhBMTcVRAztNK1qp/9Ioh8krIgcvIhvIi1xaAxh/4hKSKc4mwKqSIlYpFO64hu9qzv6j6Ap9cw5gM4ZDu3oJkli9pJ/2+9y/9XIYs7nw+sV/i1xNdgzeUbw7urvARf8PmS6/AxltNNdPslrfpPvWHtnIU8yVpwoMTCbThK9JL8ZIZQLXouTJ1Cdh2YMSfsQa8840yFoKPFMz0n2mn70lGKbaWY3wyET5KWJFMLGxTpVkkWoO5Eh+K+2g6h+R/gBo1j+GQDcG4MZ/9dtHAu0iGrFxTSJ7LtSQtlzXUH+aYUE03jmF1Hdhwdhe5WZ4PEyNCIef31ewhSwY3Xp5xlmZdqOLS7bZGdC7FomtDgiRLAzC8wEu4BVSBZqtqwg/Unf2dnqKRFVk5dayM2pc8XFRLKOzBu2FUmah4/SoXC6u1xGMpZzbkL7CWQK1JHJBvLymiQoEkxEOknzXi5hJYAtc1q21lmINPl5VPLWPGF6JWlnhxCG4XcMe9jSNIY"
							  }
						   ]
						},
						"invalid_field_names":[
						   "Test"
						],
						"partial_flavor_types":[
						   "PLATFORM"
						]
					 }`
				req, err := http.NewRequest(http.MethodPost, "/flavors", strings.NewReader(flavorJson))
				permissions := aas.PermissionInfo{
					Service: constants.ServiceName,
					Rules:   []string{constants.FlavorCreate, constants.SoftwareFlavorCreate, constants.HostUniqueFlavorCreate, constants.TagFlavorCreate},
				}
				req = comctx.SetUserPermissions(req, []aas.PermissionInfo{permissions})
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

func TestNewFlavorController(t *testing.T) {
	type args struct {
		fs        domain.FlavorStore
		fgs       domain.FlavorGroupStore
		hs        domain.HostStore
		tcs       domain.TagCertificateStore
		htm       domain.HostTrustManager
		certStore *crypt.CertificatesStore
		hcConfig  domain.HostControllerConfig
		fts       domain.FlavorTemplateStore
	}
	tests := []struct {
		name string
		args args
		want *controllers.FlavorController
	}{
		{
			name: "Valid case - Initialize flavor controller",
			args: args{
				fs:  nil,
				fgs: nil,
				hs:  nil,
				tcs: nil,
				htm: nil,
				certStore: &crypt.CertificatesStore{
					models.CertTypesFlavorSigning.String(): &crypt.CertificateStore{
						Key:          &rsa.PrivateKey{},
						CertPath:     "",
						Certificates: nil,
					},
				},
				hcConfig: domain.HostControllerConfig{},
				fts:      nil,
			},
			want: &controllers.FlavorController{
				HostCon: controllers.HostController{
					HCConfig: domain.HostControllerConfig{},
				},
				CertStore: &crypt.CertificatesStore{
					models.CertTypesFlavorSigning.String(): &crypt.CertificateStore{
						Key:          &rsa.PrivateKey{},
						CertPath:     "",
						Certificates: nil,
					},
				},
			},
		},
		{
			name: "Invalid case - Empty key",
			args: args{
				certStore: &crypt.CertificatesStore{
					models.CertTypesFlavorSigning.String(): &crypt.CertificateStore{
						CertPath:     "",
						Certificates: nil,
					},
				},
			},
			want: nil,
		},
		{
			name: "Invalid case - cert not found",
			args: args{
				certStore: &crypt.CertificatesStore{},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewFlavorController(tt.args.fs, tt.args.fgs, tt.args.hs, tt.args.tcs, tt.args.htm, tt.args.certStore, tt.args.hcConfig, tt.args.fts); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFlavorController() = %v, want %v", got, tt.want)
			}
		})
	}
}
