/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	smocks "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust/mocks"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ESXiClusterController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var esxiClusterStore *mocks.MockESXiClusterStore
	var esxiClusterController *controllers.ESXiClusterController
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController *controllers.HostController
	var hostTrustManager *smocks.MockHostTrustManager
	var hostConnectorProvider mocks2.MockHostConnectorFactory

	BeforeEach(func() {
		router = mux.NewRouter()

		esxiClusterStore = mocks.NewValidFakeESXiClusterStore()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()
		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, _ := base64.StdEncoding.DecodeString(dekBase64)

		hostControllerConfig := domain.HostControllerConfig{
			HostConnectorProvider:          hostConnectorProvider,
			DataEncryptionKey:              dek,
			Username:                       "fakeuser",
			Password:                       "fakepassword",
			VerifyQuoteForHostRegistration: false,
		}
		hostController = &controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}
		esxiClusterController = &controllers.ESXiClusterController{ECStore: esxiClusterStore,
			HController: *hostController}
	})

	// Specs for HTTP Get to "/esxi-cluster"
	Describe("Search ESXi cluster", func() {
		Context("Search esxi cluster records when no filter arguments are passed", func() {
			It("All ESXi cluster records are returned", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()

				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(2))
			})
		})

		Context("Search esxi cluster records when limit arguments are passed is invalid", func() {
			It("Status bad request to be thrown", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?limit=-1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()

				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Search esxi cluster records when limit arguments are passed is valid", func() {
			It("Records must be returned with limit set", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?limit=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()

				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when afterid arguments are passed is valid", func() {
			It("Records must be returned with rowid after afterid", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?afterId=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()

				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when afterId arguments are passed is invalid", func() {
			It("Status bad request to be thrown", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?afterId=aaa", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()

				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})

var _ = Describe("ESXiClusterController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var esxiClusterStore *mocks.MockESXiClusterStore
	var esxiClusterController *controllers.ESXiClusterController
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostCredentialStore *mocks.MockHostCredentialStore
	var hostController *controllers.HostController
	var hostTrustManager *smocks.MockHostTrustManager
	var hostConnectorProvider mocks2.MockHostConnectorFactory

	BeforeEach(func() {
		router = mux.NewRouter()

		esxiClusterStore = mocks.NewFakeESXiClusterStore()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()
		dekBase64 := "gcXqH8YwuJZ3Rx4qVzA/zhVvkTw2TL+iRAC9T3E6lII="
		dek, _ := base64.StdEncoding.DecodeString(dekBase64)

		hostControllerConfig := domain.HostControllerConfig{
			HostConnectorProvider:          hostConnectorProvider,
			DataEncryptionKey:              dek,
			Username:                       "fakeuser",
			Password:                       "fakepassword",
			VerifyQuoteForHostRegistration: false,
		}
		hostController = &controllers.HostController{
			HStore:    hostStore,
			HSStore:   hostStatusStore,
			FGStore:   flavorGroupStore,
			HCStore:   hostCredentialStore,
			HTManager: hostTrustManager,
			HCConfig:  hostControllerConfig,
		}
		esxiClusterController = &controllers.ESXiClusterController{ECStore: esxiClusterStore,
			HController: *hostController}
	})

	// Specs for HTTP Get to "/esxi-cluster"
	Describe("Search ESXi cluster", func() {
		Context("Search esxi cluster records when filtered by ESXi cluster id", func() {
			It("Should get a single ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?id=40c6ec42-ee9a-4d8a-842b-cdcd0fefa9c0", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when filtered by an invalid ESXi cluster id", func() {
			It("Should get a HTTP bad request status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet,
					"/esxi-cluster?id=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).To(HaveOccurred())
				Expect(ecCollection).To(BeNil())
			})
		})

		Context("Search esxi cluster records when filtered by ESXi cluster name", func() {
			It("Should get a single ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?clusterName=Cluster 1", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(ecCollection.ESXiCluster)).To(Equal(1))
			})
		})

		Context("Search esxi cluster records when filtered by invalid ESXi cluster name", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?clusterName=<inputdata>", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Search esxi cluster records when filtered by ESXi cluster name", func() {
			It("Should not get any ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster?clusterName=Unregistered cluster", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(ecCollection.ESXiCluster).To(BeNil())
			})
		})
	})

	Describe("Retrieve ESXi cluster record", func() {
		Context("Retrieve ESXi cluster by valid ID from data store", func() {
			It("Should retrieve ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster/f3c6a763-51cd-436c-a828-c2ce6964c823", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Try to retrieve ESXi cluster by non-existent ID from data store", func() {
			It("Should fail to retrieve ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))

				var ecCollection *hvs.ESXiClusterCollection
				err = json.Unmarshal(w.Body.Bytes(), &ecCollection)
				Expect(err).To(HaveOccurred())
				Expect(ecCollection).To(BeNil())
			})
		})

		Context("Try to retrieve ESXi cluster by existent ID from data store", func() {
			It("Should fail to retrieve ESXi cluster - search error", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/esxi-cluster/b3c6a763-51cd-436c-a828-c2ce6964c823", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})
	})

	Describe("Create ESXi cluster entry", func() {
		Context("Provide a valid ESXi cluster data", func() {
			It("Should create ESXi cluster entry", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": "New Cluster"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
		Context("Provide a existing ESXi cluster data", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": "Cluster 1"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a empty ESXi cluster data", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": ""
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid ESXi cluster data", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": "<input data"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a empty connection string", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "",
					"cluster_name": "Cluster 1"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a connection string which is not vmware", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "intel:https://ip3.com:443/sdk;u=username;p=password",
					"cluster_name": "Cluster 1"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a invalid connection string", func() {
			It("Should throw bad request error", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connection_string": "https://ta.ip.com:1443;u=admin;h=hostname()",
					"cluster_name": "Cluster 1"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide an invalid request body to create a new ESXi cluster record", func() {
			It("Should have HTTP bad request status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
					"connectionString": "https://ip3.com:443/sdk;u=username;p=password",
					"clusterName": "New Cluster"
				}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide an invalid Content-Type request body", func() {
			It("Should have HTTP 415 status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				esxiClusterRequestJson := `{
						"connection_string": "https://ip3.com:443/sdk;u=username;p=password",
						"cluster_name": "New Cluster"
					}`
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", strings.NewReader(esxiClusterRequestJson))
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide an empty request body", func() {
			It("Should have HTTP bad request status", func() {
				router.Handle("/esxi-cluster", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(
					esxiClusterController.Create))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/esxi-cluster", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})

	Describe("Delete ESXi cluster entry", func() {
		Context("Delete ESXi cluster by valid ID from data store", func() {
			It("Should Delete ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(
					esxiClusterController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/esxi-cluster/f3c6a763-51cd-436c-a828-c2ce6964c823", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})

		Context("Try to delete ESXi cluster by non-existent ID from data store", func() {
			It("Should fail to delete ESXi cluster", func() {
				router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(
					esxiClusterController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/esxi-cluster/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Describe("Delete ESXi cluster entry", func() {
			Context("Delete ESXi cluster by valid ID from data store with error in searching hosts", func() {
				It("Should return internal server error - no associated hosts for ESXI cluster", func() {
					router.Handle("/esxi-cluster/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(
						esxiClusterController.Delete))).Methods(http.MethodDelete)
					req, err := http.NewRequest(http.MethodDelete, "/esxi-cluster/a3c6a763-51cd-436c-a828-c2ce6964c823", nil)
					Expect(err).NotTo(HaveOccurred())
					w = httptest.NewRecorder()
					router.ServeHTTP(w, req)
					Expect(w.Code).To(Equal(http.StatusInternalServerError))
				})
			})
		})
	})
})

func TestNewESXiClusterController(t *testing.T) {
	type args struct {
		ec domain.ESXiClusterStore
		hc controllers.HostController
	}
	tests := []struct {
		name string
		args args
		want *controllers.ESXiClusterController
	}{
		{
			name: "Valid test case",
			args: args{
				ec: mocks.NewFakeESXiClusterStore(),
				hc: controllers.HostController{},
			},
			want: &controllers.ESXiClusterController{
				ECStore:     mocks.NewFakeESXiClusterStore(),
				HController: controllers.HostController{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewESXiClusterController(tt.args.ec, tt.args.hc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewESXiClusterController() = %v, want %v", got, tt.want)
			}
		})
	}
}
