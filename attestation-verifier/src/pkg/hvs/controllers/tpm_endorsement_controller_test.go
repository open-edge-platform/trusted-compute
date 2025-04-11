/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"github.com/gorilla/mux"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("TpmEndorsementController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var mockEndorsement *mocks2.MockTpmEndorsementStore
	var tpmEndorsmentController *controllers.TpmEndorsementController

	BeforeEach(func() {
		router = mux.NewRouter()
		mockEndorsement = mocks2.NewFakeTpmEndorsementStore()
		tpmEndorsmentController = &controllers.TpmEndorsementController{Store: mockEndorsement}
	})

	// Specs for HTTP Get to "/tpm-endorsements"
	Describe("Get list of TpmEndorsements", func() {
		Context("Get all TpmEndorsements from data store", func() {
			It("Should get list of TpmEndorsements", func() {

				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Get all TpmEndorsements from data store", func() {
			It("Should get list of TpmEndorsements with limit", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?limit=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Get all TpmEndorsements from data store", func() {
			It("Should get list of TpmEndorsements with afterId", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?afterId=1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Get the list of TPM endorsement certs when limit set is invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?limit=-1", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get the list of TPM endorsement certs when afterid set is invalid", func() {
			It("Should return bad request", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?afterId=aaa", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Search TpmEndorsements from data store based on issuerEqualTo as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?issuerEqualTo=CN=Infineon OPTIGA(TM) RSA Manufacturing CA 007,OU=OPTIGA(TM) TPM2.0,O=Infineon Technologies AG,C=DE", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on commentContains as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?commentContains=trust agent", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on hardwareUuidEqualTo filter criteria", func() {
			It("Should get list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?hardwareUuidEqualTo=ee37c360-7eae-4250-a677-6ee12adce8e3", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on commentEqualTo as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?commentEqualTo=registered by trust agent", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store based on revoked as filter criteria", func() {
			It("Should get filtered list of TpmEndorsements", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?revokedEqualTo=false", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var teCollection *hvs.TpmEndorsementCollection
				err = json.Unmarshal(w.Body.Bytes(), &teCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(teCollection.TpmEndorsement)).To(Equal(1))
			})
		})
		Context("Search TpmEndorsements from data store with invalid revoke filter criteria", func() {
			It("Should return bad request error", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?revokedEqualTo=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Search TpmEndorsements from data store based on commentContains as filter criteria with special characters", func() {
			It("Should return bad request error", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?commentContains=trust%20>-agent", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Search TpmEndorsements from data store with invalid id", func() {
			It("Should return bad request error", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements?id=ijogoirjti", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})

	// Specs for HTTP Get to "/tpm-endorsements/{endorsement_id}"
	Describe("Get TpmEndorsement by ID", func() {
		Context("Retrieve TpmEndorsement by ID from data store", func() {
			It("Should retrieve TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Try to retrieve TpmEndorsement by invalid ID from data store", func() {
			It("Should fail to retrieve TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Retrieve))).Methods(http.MethodGet)
				req, _ := http.NewRequest(http.MethodGet, "/tpm-endorsements/73755fda-c910-46be-821f-e8ddeab189e9", nil)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/tpm-endorsements/{id}"
	Describe("Delete TpmEndorsement by ID", func() {
		Context("Delete TpmEndorsement by ID from data store", func() {
			It("Should delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete TpmEndorsement, given invalid ID", func() {
			It("Should fail to delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e6", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	// Specs for HTTP Delete to "/tpm-endorsements"
	Describe("Delete TpmEndorsement by criteria", func() {
		Context("Delete TpmEndorsement for filter revoked=false", func() {
			It("Should delete TpmEndorsement", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.DeleteCollection))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/tpm-endorsements?revokedEqualTo=false", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(204))
			})
		})
		Context("Delete TpmEndorsement by incorrect ID from data store", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tpmEndorsmentController.DeleteCollection))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, "/tpm-endorsements?id=ijogoirjti", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
	// Specs for HTTP Post to "/tpm-endorsements"
	Describe("Post a new TpmEndorsement", func() {
		Context("Provide a valid TpmEndorsement data", func() {
			It("Should create a new TpmEndorsement and get HTTP Status: 201", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPost)
				tpmEndorsementJson := `{ 
                                        "hardware_uuid": "eb829e60-c8ef-46ab-ba33-6e62df3062a7",
                                        "issuer": "C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM) TPM2.0, CN = Infineon OPTIGA(TM) RSA Manufacturing CA 007",
							            "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
                                       }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide a invalid Content-Type in request", func() {
			It("Should not create a new TpmEndorsement and get HTTP Status: 415", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPost)
				tpmEndorsementJson := `{ 
                                        "hardware_uuid": "eb829e60-c8ef-46ab-ba33-6e62df3062a7",
                                        "issuer": "C = DE, O = Infineon Technologies AG, OU = OPTIGA(TM) TPM2.0, CN = Infineon OPTIGA(TM) RSA Manufacturing CA 007",
							            "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
                                       }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a TpmEndorsement data that contains duplicate hardware_uuid", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPost)
				tpmEndorsementJson := `{
                            			"hardware_uuid": "ge37c360-7eae-4250-a677-6ee12adce8e3",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
									}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a TpmEndorsement data invalid data", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPost)
				tpmEndorsementJson := `{
										"hardware_uuid": "ge37c360-7eae-4250-a677-6ee12",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
										}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/tpm-endorsements",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a empty data  in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPost)
				data := ``
				req, err := http.NewRequest(
					http.MethodPost,
					"/tpm-endorsements",
					strings.NewReader(data),
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

	// Specs for HTTP PUT to "/tpm-endorsements/{id}"
	Describe("Update TpmEndorsement", func() {
		Context("Provide a valid TpmEndorsement data", func() {
			It("Should update TpmEndorsement and get HTTP Status: 200", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Update))).Methods(http.MethodPut)
				tpmEndorsementJson := `{ 
                                        "hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e3",
                                        "issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
							            "certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
                                       }`

				req, err := http.NewRequest(
					http.MethodPut,
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Provide a TpmEndorsement data that does not exist", func() {
			It("Should get HTTP Status: 404", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Update))).Methods(http.MethodPut)
				tpmEndorsementJson := `{
										"hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e5",
										"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
										"certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
										}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e9",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})

		Context("Provide a invalid data", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Update))).Methods(http.MethodPut)
				tpmEndorsementJson := `{
                            "hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce",
							"issuer": "CN=Infineon OPTIGA(TM) RSA Manufacturing CA",
							"certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVuRENDQTRTZ0F3SUJBZ0lFS3FrTU1UQU5CZ2txaGtpRzl3MEJBUXNGQURDQmd6RUxNQWtHQTFVRUJoTUMKUkVVeElUQWZCZ05WQkFvTUdFbHVabWx1Wlc5dUlGUmxZMmh1YjJ4dloybGxjeUJCUnpFYU1CZ0dBMVVFQ3d3UgpUMUJVU1VkQktGUk5LU0JVVUUweUxqQXhOVEF6QmdOVkJBTU1MRWx1Wm1sdVpXOXVJRTlRVkVsSFFTaFVUU2tnClVsTkJJRTFoYm5WbVlXTjBkWEpwYm1jZ1EwRWdNREEzTUI0WERURTFNVEl5TWpFek1EWTBORm9YRFRNd01USXkKTWpFek1EWTBORm93QURDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBSkdldG8xRQozN2hLQ0ZHY0RZN0tWNm8zZVlLR2RwUkd0Q0NRdXRJM1hkZU9ST2ZJM0lWQUM2NDdhcEk3Yjc1KzdxOFhyQnFWCjlvSFlMS0hjTS94S3c0bTQ4L2M4VzNxUndRbHJtWEtmeGdtZXVLRWJHY2VWcUkydnJNSGlvNEdoRFJiK3BwZUkKRE44bkRPRU44dzdUZCtpT1NMNVFCTnNlTEN0UzhFMmZLU3ZpSDNZTE5lWlpHL0pTRllwQjRSN2lWL0ZhRy9LWAoyRklSL3FDaGc3RXNyK0JMKys1MkJ5RDg1Z212WTRmNmZmV0V0U2lycVlBbmhuQzRibFUzYndsMWRuYnRGVFdJCkZGVWdSUUIvUkFsWjEzVGNhcHF2UjZQTmxOS2ZYdlBLOGltSU5GYVVjSEczYUVNd1dFUFY2KzAxWk0zaDVRc0wKY2c3UDc1Z3VybVQ1UzA4Q0F3RUFBYU9DQVpnd2dnR1VNRnNHQ0NzR0FRVUZCd0VCQkU4d1RUQkxCZ2dyQmdFRgpCUWN3QW9ZL2FIUjBjRG92TDNCcmFTNXBibVpwYm1WdmJpNWpiMjB2VDNCMGFXZGhVbk5oVFdaeVEwRXdNRGN2ClQzQjBhV2RoVW5OaFRXWnlRMEV3TURjdVkzSjBNQTRHQTFVZER3RUIvd1FFQXdJQUlEQllCZ05WSFJFQkFmOEUKVGpCTXBFb3dTREVXTUJRR0JXZUJCUUlCREF0cFpEbzBPVFEyTlRnd01ERWFNQmdHQldlQkJRSUNEQTlUVEVJZwpPVFkzTUNCVVVFMHlMakF4RWpBUUJnVm5nUVVDQXd3SGFXUTZNRGN5T0RBTUJnTlZIUk1CQWY4RUFqQUFNRkFHCkExVWRId1JKTUVjd1JhQkRvRUdHUDJoMGRIQTZMeTl3YTJrdWFXNW1hVzVsYjI0dVkyOXRMMDl3ZEdsbllWSnoKWVUxbWNrTkJNREEzTDA5d2RHbG5ZVkp6WVUxbWNrTkJNREEzTG1OeWJEQVZCZ05WSFNBRURqQU1NQW9HQ0NxQwpGQUJFQVJRQk1COEdBMVVkSXdRWU1CYUFGSng5OWFrY1BVbTc1emVOU3JvUy80NTRvdGRjTUJBR0ExVWRKUVFKCk1BY0dCV2VCQlFnQk1DRUdBMVVkQ1FRYU1CZ3dGZ1lGWjRFRkFoQXhEVEFMREFNeUxqQUNBUUFDQVhRd0RRWUoKS29aSWh2Y05BUUVMQlFBRGdnRUJBQVRhSUk2VzRnOVkxMG53Z2FINzZOeE9SSWc5RWRPOU56b0RwalcrOUYvOApkdUZNKzZOMFF1Ly95QjZxcFI3WnlLWUJPZEY1ZUpMc1dGWXBqMmFrUlpoS3VpeEg2eGpSM1hHYXB2aW1XNXBUClEwNTUreGVGNWFTL3M5M1dhL2xKVk0xSnpHc1prK3ZicU13TmxJMTJzWDZ3Y2FTdElNa3VBeUtHclJkdGFmUzgKd29FS0JiNDFiVGQ3WThCdGI0azdnTURvTVUxZWtxWlNOcFQvZlI1RmYxb2IvU2d1OGx3RUNobkZqV0YyMk9qUApsZSsrbnBVeVJOby80YWE2RUM3K2hCVml0Q2lxQTlFSVBCK0RyOFVKNVpMZ09icGtMT21US25sQmE5SEw2ZnBuCnU3RUJoQi9Qb21MU29IdGhaVGpkcWw5N01yUFErWFg3T0ZyTWRVWmR6TzA9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"  
									}`

				req, err := http.NewRequest(
					http.MethodPut,
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e4",
					strings.NewReader(tpmEndorsementJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide a empty data  in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/tpm-endorsements/{id}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tpmEndorsmentController.Create))).Methods(http.MethodPut)
				data := ``
				req, err := http.NewRequest(
					http.MethodPut,
					"/tpm-endorsements/ee37c360-7eae-4250-a677-6ee12adce8e2",
					strings.NewReader(data),
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
})
