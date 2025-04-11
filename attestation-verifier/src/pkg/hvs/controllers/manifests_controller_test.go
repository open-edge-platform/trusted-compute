/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers_test

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("ManifestsController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var flavorStore *mocks.MockFlavorStore
	var manifestsController *controllers.ManifestsController
	BeforeEach(func() {
		router = mux.NewRouter()
		flavorStore = mocks.NewFakeFlavorStoreWithAllFlavors("../../lib/verifier/test_data/intel20/signed_flavors.json")
		manifestsController = &controllers.ManifestsController{
			FlavorStore: flavorStore,
		}
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a valid flavor Id", func() {
			It("Should create a manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/manifests?id=bffa1025-3605-4336-9be1-a7044cb949d6", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a flavor Id for a non SOFTWARE flavor", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/manifests?id=49705d53-a75e-414e-998e-049cbb2a0ee6", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide a flavor Id for a non existent flavor", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/manifests?id=339a7ac6-b8be-4356-ab34-be6e3bdfa1ee", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusNotFound))
			})
		})
	})

	Describe("Get manifest from flavor", func() {
		Context("Provide an invalid flavor Id", func() {
			It("Should fail to create manifest", func() {
				router.Handle("/manifests", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(manifestsController.GetManifest))).
					Methods(http.MethodGet)
				req, err := http.NewRequest(http.MethodGet, "/manifests?id=71e4c52e-595a-000000000000000429d-9917-1965b437c353", nil)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})

func TestNewManifestsController(t *testing.T) {
	type args struct {
		fs domain.FlavorStore
	}
	tests := []struct {
		name string
		args args
		want *controllers.ManifestsController
	}{
		{
			name: "Initializing controllers",
			args: args{
				fs: nil,
			},
			want: &controllers.ManifestsController{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewManifestsController(tt.args.fs); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewManifestsController() = %v, want %v", got, tt.want)
			}
		})
	}
}
