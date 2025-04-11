/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	dm "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("FlavorFromAppManifestController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostStore *mocks.MockHostStore
	var flavorController controllers.FlavorController
	var hostConnectorProvider mocks2.MockHostConnectorFactory
	var hostControllerConfig domain.HostControllerConfig
	var hostController controllers.HostController
	var flavorFromAppManifestController *controllers.FlavorFromAppManifestController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorStore = mocks.NewMockFlavorStore()
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostStore = mocks.NewMockHostStore()
		certStore := mocks.NewFakeCertificatesStore()

		(*certStore)[dm.CertTypesFlavorSigning.String()].Key, _ = rsa.GenerateKey(rand.Reader, 3072)

		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     nil,
			Username:              "fakeuser",
			Password:              "fakepassword",
		}

		hostController = controllers.HostController{
			HStore:   hostStore,
			HCConfig: hostControllerConfig,
		}

		flavorController = controllers.FlavorController{
			FStore:    flavorStore,
			FGStore:   flavorGroupStore,
			HStore:    hostStore,
			CertStore: certStore,
			HostCon:   hostController,
		}
		flavorFromAppManifestController = &controllers.FlavorFromAppManifestController{
			FlavorController: flavorController,
		}
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a valid manifest request data", func() {
			It("Should create a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
    								<connectionString>intel:https://ta-ip:1443</connectionString>
   									<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="Label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
	})

	Describe("Create a new software flavor Negative case", func() {
		Context("Provide a invalid Content-Type", func() {
			It("Should not create a new software flavor - Should return 415", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
    								<connectionString>intel:https://ta-ip:1443</connectionString>
   									<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="Label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a empty manifest request data", func() {
			It("Should not create a new software flavor - Should return 400", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/flavor-from-app-manifest", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data with no host ID or connection string", func() {
			It("Should throw an error while creating a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="Label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data for default manifest", func() {
			It("Should throw an error while creating a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
									<connectionString>intel:https://ta-ip:1443</connectionString>
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="ISecL_Default_Application_Flavor_v">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data with invalid connection string", func() {
			It("Should throw an error while creating a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
									<connectionString>intel:https://ta ip:1443</connectionString>
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="Label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data with host ID", func() {
			It("Should create a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
									<hostId>ee37c360-7eae-4250-a677-6ee12adce8e2</hostId>
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data with non existent host ID", func() {
			It("Should fail create a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
									<hostId>ee37c360-7eae-4250-a677-6ee12adce8e3</hostId>
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Create a new software flavor", func() {
		Context("Provide a manifest request data with invalid host ID", func() {
			It("Should fail to create a new software flavor", func() {
				router.Handle("/flavor-from-app-manifest", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(flavorFromAppManifestController.
					CreateSoftwareFlavor))).Methods(http.MethodPost)
				manifestRequestXml := `<ManifestRequest xmlns="lib:wml:manifests-req:1.0">
									<hostId>ee37c360-7eae-00000000004250-a677-6ee12adce8e2</hostId>
    								<Manifest xmlns="lib:wml:manifests:1.0" DigestAlg="SHA384" Label="label1">
        								<Dir Include=".*" Exclude="" Path="/opt/trustagent/bin"/>
        								<File Path="/opt/trustagent/bin/module_analysis_da.sh"/>
    								</Manifest>
									</ManifestRequest>`

				req, err := http.NewRequest(
					http.MethodPost,
					"/flavor-from-app-manifest",
					strings.NewReader(manifestRequestXml),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeXml)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

})

func TestNewFlavorFromAppManifestController(t *testing.T) {
	type args struct {
		fc controllers.FlavorController
	}
	tests := []struct {
		name string
		args args
		want *controllers.FlavorFromAppManifestController
	}{
		{
			name: "Initialize the controller",
			args: args{
				fc: controllers.FlavorController{},
			},
			want: &controllers.FlavorFromAppManifestController{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewFlavorFromAppManifestController(tt.args.fc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewFlavorFromAppManifestController() = %v, want %v", got, tt.want)
			}
		})
	}
}
