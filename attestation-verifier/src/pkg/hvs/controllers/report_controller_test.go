/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	smocks "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ReportController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var hostStore *mocks.MockHostStore

	var reportStore *mocks.MockReportStore
	var reportController *controllers.ReportController
	var hostTrustManager *smocks.MockHostTrustManager

	var hostStatusStore *mocks.MockHostStatusStore

	BeforeEach(func() {
		router = mux.NewRouter()
		hostStore = mocks.NewMockHostStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		reportStore = mocks.NewMockReportStore()
		reportController = controllers.NewReportController(reportStore, hostStore, hostStatusStore, hostTrustManager)
	})

	// Specs for HTTP Post to "/reports"
	Describe("Create a new Report", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				body := `{
							"host_name": "localhost1"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a invalid Content-Type in Create request", func() {
			It("Should not create a new Report - Should return 415", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				body := `{
							"host_name": "localhost1"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJwt)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a invalid body content in Create request", func() {
			It("Should not create a new Report - Should return 400", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				body := `{
							"host_name: "localhost1"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a invalid body content in Create request", func() {
			It("Should not create a new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a valid Create request for which host is not registered", func() {
			It("Should return bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				body := `{
							"host_id": "ee37c370-7ece-4250-a677-6ee12adce8e2"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a valid Create request for which host is registered and status is not connected", func() {
			It("Should return bad request", func() {

				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				body := `{
							"hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e2"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a Create request that contains malformed hostname", func() {
			It("Should fail to create new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3<>"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Provide a empty create request", func() {
			It("Should see an 400 error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Create))).Methods(http.MethodPost)
				hostJson := `{}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/reports/{rId}"
	Describe("Retrieve an existing Report", func() {
		Context("Retrieve Report by ID", func() {
			It("Should retrieve a Report", func() {
				router.Handle("/reports/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports/15701f03-7b1d-49f9-ac62-6b9b0728bdb3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Retrieve Report by non-existent ID", func() {
			It("Should fail to retrieve Report", func() {
				router.Handle("/reports/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Get to "/reports"
	Describe("Search for all the Reports", func() {
		Context("Get all the Reports", func() {
			It("Should get list of all the Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(2))
			})
		})
		Context("Get all the Reports", func() {
			It("Should get list of all the Reports with limit", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?limit=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})
		Context("Get all the Reports", func() {
			It("Should get list of all the Reports with afterid", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?afterId=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})
		Context("When limit is set invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?limit=-2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("When afterid is set invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?afterId=-2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Report for host with given hardware UUID", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostHardwareId=e57e5ea0-d465-461e-882d-1600090caa0d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for host with given hostname", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostName=localhost1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for host with given hostId", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostId=ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(1))
			})
		})

		Context("Get all the Report for hosts with status CONNECTED", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?hostStatus=CONNECTED", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(0))
			})
		})

		Context("Get reports with latestPerHost set to true", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var reportCollection hvs.ReportCollection
				err = json.Unmarshal(w.Body.Bytes(), &reportCollection)
				Expect(err).NotTo(HaveOccurred())
				// Verifying mocked data of reports
				Expect(len(reportCollection.Reports)).To(Equal(2))
			})
		})

		Context("Get reports with latestPerHost set to false", func() {
			It("Should get list of all the filtered Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=false", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Get reports with latestPerHost set to invalid data", func() {
			It("Should return bad request error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Get reports with invalid query parameter", func() {
			It("Should return bad request error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?testQuery=testValue", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Search Report for given invalid report id", func() {
			It("Should respond with bad request", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(reportController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?id=ee37c360-7eae-4250-a677-6ee12adce", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

			})
		})
	})

	// Specs for HTTP Post to "/reports" for accept:samlassertion+xml
	Describe("Create a new SAML Report", func() {
		Context("Provide a valid Create request", func() {
			It("Should create a new Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.CreateSaml))).Methods(http.MethodPost)
				body := `{
							"host_name": "localhost1"
						}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(body),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
				Expect(w.Header().Get("Content-Type")).To(Equal(constants.HTTPMediaTypeSaml))
			})
		})

		Context("Provide a Create request that contains malformed hostname", func() {
			It("Should fail to create Report", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.CreateSaml))).Methods(http.MethodPost)
				hostJson := `{
								"host_name": "localhost3<>"
							}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/reports",
					strings.NewReader(hostJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/reports" for accept:samlassertion+xml
	Describe("Search for all Saml Reports", func() {
		Context("Get all the Reports", func() {
			It("Should get list of all Saml Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var samlCollection []string
				err = xml.NewDecoder(w.Body).Decode(&samlCollection)
				Expect(err).NotTo(HaveOccurred())
				//TODO search should return actually 2
				Expect(len(samlCollection)).To(Equal(1))
				Expect(w.Header().Get("Content-Type")).To(Equal(constants.HTTPMediaTypeSaml))
			})
		})
		Context("Get all the Reports  with latestPerHost set to true", func() {
			It("Should get list of all Saml Reports", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var samlCollection []string
				err = xml.NewDecoder(w.Body).Decode(&samlCollection)
				Expect(err).NotTo(HaveOccurred())
				//TODO search should return actually 2
				Expect(len(samlCollection)).To(Equal(1))
				Expect(w.Header().Get("Content-Type")).To(Equal(constants.HTTPMediaTypeSaml))
			})
		})
		Context("Get all the Reports with invalid accept type", func() {
			It("Should return unsupported media error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Set invalid query parameter", func() {
			It("Should return bad request error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?Invalid=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all the Reports with invalid latestPerHost", func() {
			It("Should return bad request error", func() {
				router.Handle("/reports", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(reportController.SearchSaml))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/reports?latestPerHost=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeSaml)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
