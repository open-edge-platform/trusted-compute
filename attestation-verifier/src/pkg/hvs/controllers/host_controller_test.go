/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	smocks "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("HostController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorStore *mocks.MockFlavorStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController *controllers.HostController
	var hostTrustManager *smocks.MockHostTrustManager
	var hostControllerConfig domain.HostControllerConfig
	var hostConnectorProvider mocks2.MockHostConnectorFactory
	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorStore = mocks.NewMockFlavorStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()

		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, err := base64.StdEncoding.DecodeString(dekBase64)
		Expect(err).NotTo(HaveOccurred())
		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider:          hostConnectorProvider,
			DataEncryptionKey:              dek,
			Username:                       "fakeuser",
			Password:                       "fakepassword",
			VerifyQuoteForHostRegistration: false,
		}

		hostController = &controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FStore:    flavorStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}
	})

	// Specs for HTTP Post to "/hosts"
	Describe("Create a new Host", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://another.ta.ip.com:1443",
								"description": "Another Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a Create request that contains duplicate hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost2",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without connection string", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains malformed connection string", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://t a.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request without hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Create request that contains invalid hostname", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "local host",
								"connection_string": "intel:https://ta.ip.com:1443",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a Create request that contains invalid connection strings", func() {
			It("Should fail to create new Host", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson1 := `{
								"host_name": "localhost",
								"connection_string": "<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\">",
								"description": "Intel Host"
							}`

				hostJson2 := `{
								"host_name": "localhost",
								"connection_string": "';alert(String.fromCharCode(88,83,83))//\\';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\\\";alert(String.fromCharCode(88,83,83))//–>\">'>"",
								"description": "Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson1),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				req, err = http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson2),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a invalid Content-Type in Create request", func() {
			It("Should not create a new Host - Should return 415", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3",
								"connection_string": "intel:https://another.ta.ip.com:1443",
								"description": "Another Intel Host"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a empty body content in Create request", func() {
			It("Should not create a new Host - Should return 400", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Create))).Methods(http.MethodPost)

				req, err := http.NewRequest(http.MethodPost, "/hosts", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})

	// Specs for HTTP Get to "/hosts/{hId}"
	Describe("Retrieve an existing Host", func() {
		Context("Retrieve Host by ID", func() {
			It("Should retrieve a Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve Host by ID with invalid query parameters", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2?testQuery=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Retrieve Host by ID with invalid query value for getReport", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2?getReport=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Retrieve Host by ID with invalid query value for getTrustStatus", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2?getTrustStatus=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Retrieve Host by ID with invalid query value for getHostStatus", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2?getHostStatus=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Retrieve Host by non-existent ID", func() {
			It("Should fail to retrieve Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Put to "/hosts/{hId}"
	Describe("Update an existing Host", func() {
		Context("Provide a valid Host data", func() {
			It("Should update an existing Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								"host_name": "127.0.0.1",
								"connection_string": "intel:https://127.0.0.1:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Provide a invalid accept type", func() {
			It("Should throw unsupported media type error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								"host_name": "127.0.0.1",
								"connection_string": "intel:https://127.0.0.1:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Provide a empty body in request", func() {
			It("Should throw bad request error", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid body", func() {
			It("Should throw error in decoding the request", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								host_name: "127.0.0.1",
								"connection_string": "intel:https://127.0.0.1:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Host data that contains malformed connection string", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://t a.ip.com:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a Host data that contains invalid hostname", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								"host_name": "local host",
								"connection_string": "intel:https://ta.ip.com:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existent Host data", func() {
			It("Should fail to update Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Update))).Methods(http.MethodPut)
				hostJson := `{
								"host_name": "localhost1",
								"connection_string": "intel:https://ta.ip.com:1443"
							}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/hosts/73755fda-c910-46be-821f-e8ddeab189e9",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/hosts/{hId}"
	Describe("Delete an existing Host", func() {
		Context("Delete Host by ID", func() {
			It("Should delete a Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete Host by non-existent ID", func() {
			It("Should fail to delete Host", func() {
				router.Handle("/hosts/{hId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/hosts/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/hosts"
	Describe("Search for all the Hosts", func() {
		Context("Get all the Hosts", func() {
			It("Should get list of all the Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with specifies limit", func() {
			It("Should get list of all the Hosts with limit", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?limit=1", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts after given afterid", func() {
			It("Should get list of all the Hosts with afterId", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?afterId=1", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts when limit is invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?limit=-4", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts when afterid is invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?afterId=-4", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with key value params", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?key=os_name&value=RedHatEnterprise", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 0 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(0))
			})
		})
		Context("Get all the Hosts with valid nameEqualTo param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?nameEqualTo=localhost1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with valid nameContains param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?nameContains=localhost", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 2 hosts
				Expect(len(hostCollection.Hosts)).To(Equal(2))
			})
		})
		Context("Get all the Hosts with invalid nameEqualTo param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?nameEqualTo=local host1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with invalid nameContains param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?nameContains=local host", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with valid id param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?id=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with valid hostHardwareId param", func() {
			It("Should get list of all the filtered Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?hostHardwareId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostCollection hvs.HostCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host
				Expect(len(hostCollection.Hosts)).To(Equal(1))
			})
		})
		Context("Get all the Hosts with invalid id param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?id=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Hosts with invalid hostHardwareId param", func() {
			It("Should fail to get Hosts", func() {
				router.Handle("/hosts", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts?hostHardwareId=e57e5ea0-d465-461e-882d-", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Post to "/hosts/{hId}/flavorgroups"
	Describe("Create a new Host Flavorgroup link", func() {
		Context("Provide a valid Flavorgroup Id", func() {
			It("Should create a new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "ee37c360-7eae-4250-a677-6ee12adce8e2"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a invalid content type", func() {
			It("Should return unsupported media error", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "ee37c360-7eae-4250-a677-6ee12adce8e2"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Provide a empty body in request", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					nil,
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid uuid in request", func() {
			It("Should return bad request error", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "00000000-0000-0000-0000-000000000000"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a linked Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-1600090caa0d"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a non-existing Host Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-1600090caa0d"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Provide a non-existing Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "73755fda-c910-46be-821f-e8ddeab189e9"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide an invalid Flavorgroup Id", func() {
			It("Should fail to create new Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.AddFlavorgroup))).Methods(http.MethodPost)
				hostJson := `{
								"flavorgroup_id": "e57e5ea0-d465-461e-882d-"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/hosts/{hId}/flavorgroups/{fgId}"
	Describe("Retrieve an existing Host Flavorgroup link", func() {
		Context("Retrieve by Host Id and Flavorgroup Id", func() {
			It("Should retrieve a Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Retrieve by non-existent Host Id", func() {
			It("Should fail to retrieve Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Retrieve by non-existent Flavorgroup Id", func() {
			It("Should fail to retrieve Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.RetrieveFlavorgroup))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/hosts/{hId}/flavorgroups/{fgId}"
	Describe("Delete an existing Host Flavorgroup link", func() {
		Context("Delete by host Id and Flavorgroup Id", func() {
			It("Should delete a Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete by non-existent Host Id", func() {
			It("Should fail to delete Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/hosts/73755fda-c910-46be-821f-e8ddeab189e9/flavorgroups/", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
		Context("Delete by non-existent Flavorgroup Id", func() {
			It("Should fail to delete Host Flavorgroup link", func() {
				router.Handle("/hosts/{hId}/flavorgroups/{fgId}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(hostController.RemoveFlavorgroup))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/hosts/{hId}/flavorgroups"
	Describe("Search for all the Host Flavorgroup links", func() {
		Context("Get all the Host Flavorgroup links for a Host", func() {
			It("Should get list of all the Host Flavorgroup links associated with Host", func() {
				router.Handle("/hosts/{hId}/flavorgroups", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(hostController.SearchFlavorgroups))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/hosts/ee37c360-7eae-4250-a677-6ee12adce8e2/flavorgroups", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var hostFlavorgroupCollection hvs.HostFlavorgroupCollection
				err = json.Unmarshal(w.Body.Bytes(), &hostFlavorgroupCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of 1 host flavorgroup link
				Expect(len(hostFlavorgroupCollection.HostFlavorgroups)).To(Equal(1))
			})
		})
	})
})

func TestGenerateConnectionString(t *testing.T) {
	type args struct {
		cs       string
		username string
		password string
		hc       domain.HostCredentialStore
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Valid connection string - linux host",
			args: args{
				cs:       "intel:https://fakehost",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "intel:https://fakehost;u=fakeuser;p=fakepass",
			wantErr: false,
		},
		{
			name: "Valid connection string - vmware host",
			args: args{
				cs:       "vmware:https://vCenterServer.com:443/sdk;h=trustagent.server.com;u=vCenterUsername;p=vCenterPassword",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "vmware:https://vCenterServer.com:443/sdk;h=trustagent.server.com;u=vCenterUsername;p=vCenterPassword",
			wantErr: false,
		},
		{
			name: "Invalid connection string - invalid hostname provided - vmware host",
			args: args{
				cs:       "vmware:https://vCenterServer.com:443/sdk;h=trustagent.server.com;",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Valid connection string - Valid hostname provided - vmware host",
			args: args{
				cs:       "vmware:https://vCenterServer.com:443/sdk;h=fakehost;",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "vmware:https://vCenterServer.com:443/sdk;h=fakehost;;u=fakeuser;p=fakepass",
			wantErr: false,
		},
		{
			name: "Invalid connection string -  empty hostname provided - vmware host",
			args: args{
				cs:       "vmware:https://vCenterServer.com:443/sdk;h=;",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Invalid connection string - hostname not provided - vmware host",
			args: args{
				cs:       "vmware:https://vCenterServer.com:443/sdk;",
				username: "fakeuser",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error case - user name not provided",
			args: args{
				cs:       "intel:https://fakehost",
				username: "",
				password: "fakepass",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error case - password not provided",
			args: args{
				cs:       "intel:https://fakehost",
				username: "fakeuser",
				password: "",
				hc:       mocks.NewMockHostCredentialStore(),
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := controllers.GenerateConnectionString(tt.args.cs, tt.args.username, tt.args.password, tt.args.hc)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateConnectionString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GenerateConnectionString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_PopulateHostInfoFetchCriteria(t *testing.T) {
	type args struct {
		params url.Values
	}
	tests := []struct {
		name    string
		args    args
		want    *models.HostInfoFetchCriteria
		wantErr bool
	}{
		{
			name: "Fetch using all host info criteria",
			args: args{
				params: url.Values{"getReport": []string{"true"}, "getTrustStatus": []string{"true"}, "getHostStatus": []string{"true"}},
			},
			want: &models.HostInfoFetchCriteria{
				GetReport:      true,
				GetTrustStatus: true,
				GetHostStatus:  true,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := controllers.PopulateHostInfoFetchCriteria(tt.args.params)
			if (err != nil) != tt.wantErr {
				t.Errorf("PopulateHostInfoFetchCriteria() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PopulateHostInfoFetchCriteria() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewHostController(t *testing.T) {
	type args struct {
		hs  domain.HostStore
		hss domain.HostStatusStore
		fs  domain.FlavorStore
		fgs domain.FlavorGroupStore
		hcs domain.HostCredentialStore
		htm domain.HostTrustManager
		hcc domain.HostControllerConfig
	}
	tests := []struct {
		name string
		args args
		want *controllers.HostController
	}{
		{
			name: "Initializing controllers",
			args: args{
				hs:  nil,
				hss: nil,
				fs:  nil,
				fgs: nil,
				hcs: nil,
				htm: nil,
				hcc: domain.HostControllerConfig{},
			},
			want: &controllers.HostController{HCConfig: domain.HostControllerConfig{}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewHostController(tt.args.hs, tt.args.hss, tt.args.fs, tt.args.fgs, tt.args.hcs, tt.args.htm, tt.args.hcc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewHostController() = %v, want %v", got, tt.want)
			}
		})
	}
}
