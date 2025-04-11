/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	host_connector "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

const (
	tagCASigningCertPath  = "../domain/mocks/resources/tagcert-scert.pem"
	tagCASigningKeyPath   = "../domain/mocks/resources/tagcert-skey.pem"
	flavorSigningCertPath = "../domain/mocks/resources/flavor-scert.pem"
	flavorSigningKeyPath  = "../domain/mocks/resources/flavor-skey.pem"
)

func setupCertsStore() *crypt.CertificatesStore {
	var tagKey, fsKey crypto.PrivateKey

	//Generate TagCA Keypair
	caCertBytes, key, err := crypt.CreateKeyPairAndCertificate(consts.DefaultCertIssuer, "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
	if err != nil {
		log.WithError(err).Errorf("Failed create certificate")
	}
	err = crypt.SavePrivateKeyAsPKCS8(key, tagCASigningKeyPath)
	if err != nil {
		log.WithError(err).Errorf("Failed save private key")
	}
	err = crypt.SavePemCert(caCertBytes, tagCASigningCertPath)
	if err != nil {
		log.WithError(err).Errorf("Failed save certificate")
	}
	tagKey, err = crypt.GetPrivateKeyFromPKCS8File(tagCASigningKeyPath)
	if err != nil {
		log.WithError(err).Errorf("Failed get private key")
	}
	certMap, err := crypt.GetSubjectCertsMapFromPemFile(tagCASigningCertPath)
	if err != nil {
		log.WithError(err).Errorf("Failed get certificate")
	}

	var tagCAStore = crypt.CertificateStore{
		Key:          tagKey,
		CertPath:     tagCASigningCertPath,
		Certificates: certMap,
	}

	var caCertsStore = *mocks2.NewFakeCertificatesStore()

	// Generate flavor signing Keypair
	caCertBytes, key, err = crypt.CreateKeyPairAndCertificate(consts.DefaultCN, "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
	if err != nil {
		log.WithError(err).Errorf("Failed create certificate")
	}
	err = crypt.SavePrivateKeyAsPKCS8(key, flavorSigningKeyPath)
	if err != nil {
		log.WithError(err).Errorf("Failed save private key")
	}
	err = crypt.SavePemCert(caCertBytes, flavorSigningCertPath)
	if err != nil {
		log.WithError(err).Errorf("Failed save certificate")
	}
	fsKey, err = crypt.GetPrivateKeyFromPKCS8File(flavorSigningKeyPath)
	if err != nil {
		log.WithError(err).Errorf("Failed get private key")
	}
	certMap, err = crypt.GetSubjectCertsMapFromPemFile(flavorSigningCertPath)
	if err != nil {
		log.WithError(err).Errorf("Failed get certificate")
	}

	var flavorCAStore = crypt.CertificateStore{
		Key:          fsKey,
		CertPath:     flavorSigningCertPath,
		Certificates: certMap,
	}

	caCertsStore[models.CaCertTypesTagCa.String()] = &tagCAStore
	caCertsStore[models.CertTypesFlavorSigning.String()] = &flavorCAStore

	return &caCertsStore
}

var _ = Describe("TagCertificateController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var caCertsStore *crypt.CertificatesStore
	var tagCertStore *mocks2.MockTagCertificateStore
	var hostStore *mocks2.MockHostStore
	var flavorStore *mocks2.MockFlavorStore
	var flavorGroupStore *mocks2.MockFlavorgroupStore
	var tagCertController *controllers.TagCertificateController
	caCertsStore = setupCertsStore()

	BeforeEach(func() {
		router = mux.NewRouter()
		tagCertStore = mocks2.NewMockTagCertificateStore()
		hostStore = mocks2.NewMockHostStore()
		flavorStore = mocks2.NewMockFlavorStore()
		flavorGroupStore = mocks2.NewFakeFlavorgroupStore()
		// inject MockHostConnector into the TagCertController
		hcp := mocks.MockHostConnectorFactory{}
		tcc := domain.TagCertControllerConfig{
			AASApiUrl:       "/fakeaas",
			ServiceUsername: "fakeuser",
			ServicePassword: "fakepassword",
		}

		tagCertController = controllers.NewTagCertificateController(tcc, *caCertsStore, tagCertStore, nil, hostStore, flavorStore, flavorGroupStore, hcp)
	})

	Describe("Create TagCertificates", func() {
		Context("When a empty TagCertificate Create Request is passed", func() {
			It("A HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Create))).Methods(http.MethodPost)

				// Create Request body
				createTcReq := ``

				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When a Invalid Content-Type given in Create Request", func() {
			It("A HTTP Status: 415 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Create))).Methods(http.MethodPost)

				// Create Request body
				createTcReq := ``

				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJwt)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("When a VALID TagCertificate Create Request is passed", func() {
			It("A new TagCertificate record is created and HTTP Status: 201 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Create))).Methods(http.MethodPost)

				// Create Request body
				createTcReq := `{ "hardware_uuid" : "fda6105d-a340-42da-bc35-0555e7a5e360", "selection_content" : [ { "name" : "Location", "value" : "SantaClara" }, { "name" : "Company", "value" : "IntelCorporation" } ] }`

				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("When an INVALID TagCertificate Create Request with an empty hardware_uuid is passed", func() {
			It("A new TagCertificate record is NOT created and HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Create))).Methods(http.MethodPost)

				// Create Request body
				createTcReq := `{"hardware_uuid" : "", "selection_content": [{ "name" : "Location", "value" : "SantaClara" }, { "name" : "Company", "value" : "IntelCorporation"}]}`

				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When an INVALID TagCertificate Create Request with no SelectionContent  is passed", func() {
			It("A new TagCertificate record is NOT created and HTTP Status: 400 response is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Create))).Methods(http.MethodPost)

				// Create Request body
				createTcReq := `{ "hardware_uuid" : "fda6105d-a340-42da-bc35-0555e7a5e360"}`

				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateEndpointPath,
					strings.NewReader(createTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	// Specs for HTTP Get to "/tag-certificates"
	Describe("Search TagCertificates", func() {
		Context("When no filter arguments are passed", func() {
			It("All TagCertificate records are returned and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath, nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(8))
			})
		})

		Context("When unknown filter arguments are passed", func() {
			It("400 response code is received", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?badparam=true", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("When filtered by TagCertificate id", func() {
			It("Should get a single TagCertificate entry and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?id=fda6105d-a340-42da-bc35-0555e7a5e360", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(1))
			})
		})

		Context("When filtered by a non-existent TagCertificate id", func() {
			It("Should get an empty list of TagCertificates and 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?id=b47a13b1-0af2-47d6-91d0-717094bfda2d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("When filtered by an invalid TagCertificate id", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?id=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		// HardwareUUID
		Context("When filtered by HardwareUUID id", func() {
			It("Should get a list of TagCertificate entries with the corresponding HardwareUUID and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=80ecce40-04b8-e811-906e-00163566263e", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(1))
			})
		})

		Context("When filtered by a non-existent HardwareUUID id", func() {
			It("Should get an empty list of TagCertificates and 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=b47a13b1-0af2-47d6-91d0-717094bfda2d", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("When filtered by an invalid HardwareUUID id", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?hardwareUuid=13885605-a0ee-41f20000000000000000000000-b6fc-fd82edc487ad", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("When filtered by a valid SubjectEqualTo", func() {
			It("Should get a list of TagCertificates filtered by Subject=SubjectEqualTo and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?subjectEqualTo=00ecd3ab-9af4-e711-906e-001560a04062", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(2))
			})
		})

		Context("When filtered by a non-existent SubjectEqualTo", func() {
			It("Should get an empty list of TagCertificates and a 200 OK response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?subjectEqualTo=afc82547-0691-4be1-8b14-bcebfce86fd6", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("When filtered by a valid SubjectContains", func() {
			It("Should get a list of TagCertificates that contains the SubjectContains parameter and a 200 OK response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?subjectContains=001560a04062", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(2))
			})
		})

		Context("When filtered by a non-existent SubjectContains", func() {
			It("Should get an empty list of TagCertificates and a 200 response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?subjectContains=7a466a5beff9", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("When filtered by a valid IssuerEqualTo", func() {
			It("Should get a list of TagCertificates filtered by Issuer=IssuerEqualTo and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?issuerEqualTo=CN=asset-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates) > 0).To(BeTrue())
			})
		})

		Context("When filtered by a non-existent IssuerEqualTo", func() {
			It("Should get an empty list of TagCertificates and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?issuerEqualTo=CN=nonexistent-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("When filtered by a valid IssuerContains", func() {
			It("Should get a list of TagCertificates that contains the IssuerContains parameter and a 200 response Code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?issuerContains=asset-tag", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(tcCollection.TagCertificates) > 0).To(BeTrue())
			})
		})

		Context("When filtered by a non-existent IssuerContains", func() {
			It("Should get an empty list of TagCertificates and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?issuerContains=nonexistent-tag-service", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).NotTo(HaveOccurred())
				Expect(tcCollection.TagCertificates).To(BeEmpty())
			})
		})

		Context("Search TagCertificates from data store with valid ValidOn date", func() {
			It("Should return a list of TagCertificates valid on the ValidOn date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validOn=2016-09-28T09:08:33.913Z", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(tcCollection.TagCertificates).ToNot(BeEmpty())
			})
		})

		Context("Search TagCertificates from data store with valid ValidBefore date", func() {
			It("Should return a list of TagCertificates which are valid before the ValidBefore date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validBefore=2016-09-28T09:08:33.913Z", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(1))
			})
		})

		Context("Search TagCertificates from data store with valid ValidAfter", func() {
			It("Should return a list of TagCertificates which are valid after the ValidAfter date and a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validAfter=2040-09-28T09:08:33.913Z", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).ToNot(HaveOccurred())
				Expect(len(tcCollection.TagCertificates)).To(Equal(1))
			})
		})

		Context("Search TagCertificates from data store with invalid ValidOn date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validOn="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(consts.ParamDateTimeFormat)+"0000000000000", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("Search TagCertificates from data store with invalid ValidBefore date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validBefore="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(consts.ParamDateTimeFormat)+"01010101010", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

		Context("Search TagCertificates from data store with invalid ValidAfter date", func() {
			It("Should get an empty list of TagCertificates and a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Search))).Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, hvsRoutes.TagCertificateEndpointPath+"?validAfter="+time.Now().Add(-mocks2.TimeDuration12Hrs).Format(consts.ParamDateTimeFormat)+"ABC", nil)
				Expect(err).ToNot(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))

				var tcCollection *hvs.TagCertificateCollection
				err = json.Unmarshal(w.Body.Bytes(), &tcCollection)
				Expect(err).To(HaveOccurred())
				Expect(tcCollection).To(BeNil())
			})
		})

	})

	// Specs for HTTP DELETE to "/tag-certificates/{tagcertificate_id}"
	Describe("Delete TagCertificate by ID", func() {
		Context("Delete TagCertificate by ID from data store", func() {
			It("Should delete TagCertificate and return a 200 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath+"/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, hvsRoutes.TagCertificateEndpointPath+"/cf197a51-8362-465f-9ec1-d88ad0023a27", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNoContent))
			})
		})
		Context("Delete TagCertificate by incorrect ID from data store", func() {
			It("Should fail to delete TagCertificate and return a 404 response code", func() {
				router.Handle(hvsRoutes.TagCertificateEndpointPath+"/{id}", hvsRoutes.ErrorHandler(hvsRoutes.ResponseHandler(tagCertController.Delete))).Methods(http.MethodDelete)
				req, err := http.NewRequest(http.MethodDelete, hvsRoutes.TagCertificateEndpointPath+"/c00135a8-f5e9-4860-ae6c-4acce525d340", nil)
				Expect(err).NotTo(HaveOccurred())
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	//-------TagCertificate DEPLOY Tests---------------------

	// Specs for HTTP POST to "/rpc/deploy-tag-certificate"
	Describe("Deploy TagCertificate", func() {
		Context("Deploy valid TagCertificate to a connected Linux host", func() {
			It("Should deploy a TagCertificate to the connected host", func() {
				// we inject the MockTAClient into the controller
				aasBaseURL := "/aas/v1"
				config.Global().AASApiUrl = aasBaseURL

				hostUrl := "intel:https://fakehost;u=fakeuser;p=fakepass"

				hardwareUUID := uuid.MustParse("7a569dad-2d82-49e4-9156-069b0065b262")

				newId, err := uuid.NewRandom()
				Expect(err).NotTo(HaveOccurred())
				_, _ = tagCertController.HostStore.Create(&hvs.Host{
					Id:               newId,
					HostName:         "MyFakeHost",
					Description:      "Fakest Connected Host In The World",
					ConnectionString: hostUrl,
					HardwareUuid:     &hardwareUUID,
				})

				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				// Deploy Request body
				deployTcReq := `{ "certificate_id" : "cf197a51-8362-465f-9ec1-d88ad0023a27" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Deploy valid TagCertificate to a disconnected Linux host but Deploy Operation fails", func() {
			It("Should return a 500 Error Code response", func() {
				// we inject the MockTAClient into the controller
				aasBaseURL := "/aas"
				config.Global().AASApiUrl = aasBaseURL

				hostUrl := "intel:/fakebadhost;u=fakeuser;p=fakepass"

				hardwareUUID := uuid.MustParse("00e4d709-8d72-44c3-89ae-c5edc395d6fe")

				newId, err := uuid.NewRandom()
				Expect(err).NotTo(HaveOccurred())
				_, _ = tagCertController.HostStore.Create(&hvs.Host{
					Id:               newId,
					HostName:         "MyFakeBadHost",
					Description:      "Fakest Disconnected Host In The World",
					ConnectionString: hostUrl,
					HardwareUuid:     &hardwareUUID,
				})

				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				// Deploy Request body
				deployTcReq := `{ "certificate_id" : "7ce60664-faa3-4c2e-8c45-41e209e4f1db" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Deploy expired TagCertificate to a connected Linux host", func() {
			It("Should fail to deploy TagCertificate and return a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				deployTcReq := `{ "certificate_id" : "390784a9-d83f-4fa1-b6b5-a77bd13a3c7b" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Deploy non-existent TagCertificate to a connected Linux host", func() {
			It("Should fail to deploy TagCertificate and return a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				deployTcReq := `{ "certificate_id" : "146fffdb-97b9-4b5d-9b59-17c6e8248493" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Deploy invalid TagCertificate to a connected Linux host", func() {
			It("Should fail to deploy TagCertificate and return a 400 response code", func() {
				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				deployTcReq := `{ "certificate_id" : "73755fda-c910-46be-821f-xyxyz" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)

				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Deploy valid TagCertificate to a Linux host that does not have a entry in the Host table", func() {
			It("Should return a 400 Error Code response", func() {
				// we inject the MockTAClient into the controller
				aasBaseURL := "/aas"
				config.Global().AASApiUrl = aasBaseURL

				newId, err := uuid.NewRandom()
				Expect(err).NotTo(HaveOccurred())
				hwId, err := uuid.NewRandom()
				Expect(err).NotTo(HaveOccurred())
				newTC, _ := tagCertController.Store.Create(&hvs.TagCertificate{
					ID:           newId,
					Certificate:  nil,
					Subject:      "CN=Does Not Compute",
					Issuer:       "Fake CA",
					NotBefore:    time.Now(),
					NotAfter:     time.Now().AddDate(1, 0, 0),
					HardwareUUID: hwId,
				})

				router.Handle(hvsRoutes.TagCertificateDeployEndpointPath, hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(tagCertController.Deploy))).Methods(http.MethodPost)
				// Deploy Request body
				deployTcReq := `{ "certificate_id" :  "` + newTC.ID.String() + `" }`
				req, err := http.NewRequest(
					http.MethodPost,
					hvsRoutes.TagCertificateDeployEndpointPath,
					strings.NewReader(deployTcReq),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})

func TestNewTagCertificateController(t *testing.T) {
	certStoreMissingTagCA := setupCertsStore()
	delete(*certStoreMissingTagCA, models.CaCertTypesTagCa.String())

	certStoreMissingFSCA := setupCertsStore()
	delete(*certStoreMissingFSCA, models.CaCertTypesTagCa.String())
	type args struct {
		certStore *crypt.CertificatesStore
		tcs       domain.TagCertificateStore
		hs        domain.HostStore
		fs        domain.FlavorStore
		fgs       domain.FlavorGroupStore
		hcp       host_connector.HostConnectorProvider
		htm       domain.HostTrustManager
	}
	tests := []struct {
		name string
		args args
		want *controllers.TagCertificateController
	}{
		{
			name: "CertStore missing TagCA to NewTagCertificateController",
			args: args{
				certStore: certStoreMissingTagCA,
				tcs:       mocks2.NewMockTagCertificateStore(),
			},
		},
		{
			name: "CertStore missing Flavor Signing CA to NewTagCertificateController",
			args: args{
				certStore: certStoreMissingFSCA,
				tcs:       mocks2.NewMockTagCertificateStore(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewTagCertificateController(domain.TagCertControllerConfig{}, *tt.args.certStore, tt.args.tcs, tt.args.htm, tt.args.hs, tt.args.fs, tt.args.fgs, tt.args.hcp); got != nil {
				t.Errorf("TagCertificateController should be non-nil")
			}
		})
	}

	// cleanup
	err := os.Remove(flavorSigningCertPath)
	Expect(err).NotTo(HaveOccurred())
	err = os.Remove(flavorSigningKeyPath)
	Expect(err).NotTo(HaveOccurred())
	err = os.Remove(tagCASigningCertPath)
	Expect(err).NotTo(HaveOccurred())
	err = os.Remove(tagCASigningKeyPath)
	Expect(err).NotTo(HaveOccurred())
}
