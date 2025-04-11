/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("CaCertificatesController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	certStore, _ := crypt.LoadCertificates(mocks2.NewFakeCertificatesPathStore(), models.GetUniqueCertTypes())
	var caCertificatesController *controllers.CaCertificatesController
	BeforeEach(func() {
		router = mux.NewRouter()
		caCertificatesController = &controllers.CaCertificatesController{CertStore: certStore}
	})

	// Specs for HTTP Post to "/ca-certificates"
	Describe("Create root CA certificates", func() {
		Context("Create root CA certificates", func() {
			It("Should create CA certificates with CN", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods(http.MethodPost)
				cert, _, _ := crypt.CreateKeyPairAndCertificate("root-test", "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
				certificate := hvs.CaCertificate{
					Name:        "root-test",
					Type:        models.CaCertTypesRootCa.String(),
					Certificate: cert,
				}
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					http.MethodPost,
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Create root CA certificates with invalid content type", func() {
			It("Should return bad request error", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods(http.MethodPost)
				cert, _, _ := crypt.CreateKeyPairAndCertificate("root-test", "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
				certificate := hvs.CaCertificate{
					Name:        "root-test",
					Type:        models.CaCertTypesRootCa.String(),
					Certificate: cert,
				}
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					http.MethodPost,
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJwt)
				Expect(err).ToNot(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})
		Context("Create root CA certificates with invalid certificate type", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods(http.MethodPost)
				certificate := hvs.CaCertificate{
					Name: "root-test",
					Type: models.CaCertTypesTagCa.String(),
				}
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					http.MethodPost,
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Create root CA certificates with invalid payload", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods(http.MethodPost)
				certificate := ""
				payload, _ := json.Marshal(certificate)
				req, err := http.NewRequest(
					http.MethodPost,
					"/ca-certificates",
					bytes.NewBuffer(payload),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Create root CA certificates with empty body", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Create))).Methods(http.MethodPost)
				req, err := http.NewRequest(
					http.MethodPost,
					"/ca-certificates",
					nil,
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

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Endorsement CA certificates", func() {
		Context("Get all Endorsement CA certificates with search endorsement", func() {
			It("Should get list of Endorsement CA certificates", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get all Endorsement CA certificates with search endorsement with invalid query parameter", func() {
			It("Should return bad request error", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?test=endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get all Endorsement CA certificates", func() {
			It("Should get list of Endorsement CA certificates with search ek", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=ek", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get certificates with invalid domain", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=dumb", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get SAML certificates", func() {
		Context("Get all SAML certificates", func() {
			It("Should get list of SAML certificates with associated CA", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get SAML certificate", func() {
		Context("Get SAML certificate", func() {
			It("Should get SAML certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/saml", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCertCollection *hvs.CaCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &caCertCollection)
				Expect(err).NotTo(HaveOccurred())
				log.Info(len(caCertCollection.CaCerts))
			})
		})
		Context("Get certificate with invalid type", func() {
			It("Should return bad request", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/dumb", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Privacy CA certificate", func() {
		Context("Get all Privacy CA certificate with keyword privacy", func() {
			It("Should get Privacy CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/privacy", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Get all Privacy CA certificate with keyword aik", func() {
			It("Should get Privacy CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/aik", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get Endorsement CA certificate", func() {
		Context("Get all Endorsement CA certificate with keyword endorsement", func() {
			It("Should get Endorsement CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
		Context("Get all Endorsement CA certificate with keyword ek", func() {
			It("Should get Endorsement CA certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/ek", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})
	// Specs for HTTP Get to "/ca-certificates"
	Describe("Get TLS certificate", func() {
		Context("Get TLS certificate", func() {
			It("Should get TLS certificate", func() {
				router.Handle("/ca-certificates/{certType}", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.Retrieve))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates/tls", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var caCert *hvs.CaCertificate
				err = json.Unmarshal(w.Body.Bytes(), &caCert)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("Get pem certificates", func() {
		Context("Get pem certificates", func() {
			It("Should get pem certificates", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.SearchPem))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
		Context("Get pem certificates with invalid query parameters", func() {
			It("Should return bad request error", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.SearchPem))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?test=endorsement", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
		Context("Get pem certificates with invalid domain type", func() {
			It("Should return bad request error", func() {
				router.Handle("/ca-certificates", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(caCertificatesController.SearchPem))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/ca-certificates?domain=test", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
