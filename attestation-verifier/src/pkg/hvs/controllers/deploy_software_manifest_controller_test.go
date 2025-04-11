/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("DeploySoftwareManifestController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var flavorGroupStore *mocks.MockFlavorgroupStore
	var hostStore *mocks.MockHostStore
	var hostStatusStore *mocks.MockHostStatusStore
	var hostTrustManager *smocks.MockHostTrustManager
	var hostConnectorProvider mocks2.MockHostConnectorFactory
	var hostControllerConfig domain.HostControllerConfig
	var hostController controllers.HostController
	var hostCredentialStore *mocks.MockHostCredentialStore
	var deploySoftwareManifestController *controllers.DeploySoftwareManifestController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorStore = mocks.NewFakeFlavorStoreWithAllFlavors("../../lib/verifier/test_data/intel20/signed_flavors.json")
		flavorGroupStore = mocks.NewFakeFlavorgroupStore()
		hostStatusStore = mocks.NewMockHostStatusStore()
		hostStore = mocks.NewMockHostStore()
		hostCredentialStore = mocks.NewMockHostCredentialStore()

		hostControllerConfig = domain.HostControllerConfig{
			HostConnectorProvider: hostConnectorProvider,
			DataEncryptionKey:     nil,
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

		deploySoftwareManifestController = &controllers.DeploySoftwareManifestController{
			FlavorStore: flavorStore,
			HController: hostController,
		}
	})

	Describe("Deploy software manifest to host", func() {
		Context("Provide a valid host ID and flavor ID", func() {
			It("Should deploy software manifest successfully", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"7f0683c1-a038-4ed4-8b29-286410f2e753",
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})

	Describe("Deploy software manifest to host - Negative cases", func() {
		Context("Provide a invalid Content-Type", func() {
			It("Should not deploy software manifest - should return 415", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"7f0683c1-a038-4ed4-8b29-286410f2e753",
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJwt)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide a empty body content in request", func() {
			It("Should not deploy software manifest - should return 400", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				req, err := http.NewRequest(http.MethodPost, "/rpc/deploy-software-manifest", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				req.Header.Set("Accept", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Deploy software manifest to host", func() {
		Context("Provide invalid flavor ID in request", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"339a7ac6-b8be-000000004356-ab34-be6e3bdfa1ed",
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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

	Describe("Deploy software manifest to host", func() {
		Context("Provide invalid host ID in request", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"339a7ac6-b8be-4356-ab34-be6e3bdfa1ed",
												"host_id":"ee37c360-7eae-000000004250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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

	Describe("Deploy software manifest to host", func() {
		Context("Do not provide host ID in request", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"339a7ac6-b8be-4356-ab34-be6e3bdfa1ed"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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

	Describe("Deploy software manifest to host", func() {
		Context("Do not provide flavor ID in request", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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

	Describe("Deploy software manifest to host", func() {
		Context("Provide flavor ID for non software flavor", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"71e4c52e-595a-429d-9917-1965b437c353"
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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
	Describe("Deploy software manifest to host", func() {
		Context("Provide flavor ID for non existent flavor", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"71e4c52e-595a-429d-9917-1965b437c354"
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e2"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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
	Describe("Deploy software manifest to host", func() {
		Context("Provide host ID for non existent host", func() {
			It("Should fail to deploy software manifest", func() {
				router.Handle("/rpc/deploy-software-manifest", hvsRoutes.ErrorHandler(hvsRoutes.
					JsonResponseHandler(deploySoftwareManifestController.DeployManifest))).Methods(http.MethodPost)
				deployManifestRequestJson := `{
												"flavor_id":"71e4c52e-595a-429d-9917-1965b437c353"
												"host_id":"ee37c360-7eae-4250-a677-6ee12adce8e3"
											  }`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/deploy-software-manifest",
					strings.NewReader(deployManifestRequestJson),
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

func TestNewDeploySoftwareManifestController(t *testing.T) {
	type args struct {
		fs domain.FlavorStore
		hc controllers.HostController
	}
	tests := []struct {
		name string
		args args
		want *controllers.DeploySoftwareManifestController
	}{
		{
			name: "Initialize new deploy software manifest controller",
			args: args{
				fs: mocks.NewMockFlavorStore(),
				hc: controllers.HostController{},
			},
			want: &controllers.DeploySoftwareManifestController{
				FlavorStore: mocks.NewMockFlavorStore(),
				HController: controllers.HostController{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewDeploySoftwareManifestController(tt.args.fs, tt.args.hc); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDeploySoftwareManifestController() = %v, want %v", got, tt.want)
			}
		})
	}
}
