/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"

	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/controllers"
	tagentRouter "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/router"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"gopkg.in/yaml.v3"
)

const (
	platformInfoFilePath = "../test/resources/platform-info"
)

var _ = Describe("GetPlatformInfo Request", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder

	// Read Config
	testCfg, err := os.ReadFile(testConfig)
	if err != nil {
		log.Fatalf("Failed to load test tagent config file %v", err)
	}
	var tagentConfig *config.TrustAgentConfiguration
	yaml.Unmarshal(testCfg, &tagentConfig)

	testConfig_test, err := os.ReadFile(testConfig_test)
	if err != nil {
		log.Fatalf("Failed to load test tagent config file %v", err)
	}
	var testConfig *config.TrustAgentConfiguration
	yaml.Unmarshal(testConfig_test, &testConfig)

	var reqHandler common.RequestHandler
	var negReqHandler common.RequestHandler

	BeforeEach(func() {
		router = mux.NewRouter()
		reqHandler = common.NewMockRequestHandler(tagentConfig)
		negReqHandler = common.NewMockRequestHandler(testConfig)
	})

	Describe("GetPlatformInfo", func() {
		Context("GetPlatformInfo request", func() {
			It("Should perform GetPlatformInfo", func() {
				router.HandleFunc("/v2/host", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetPlatformInfo(reqHandler, platformInfoFilePath), []string{"host_info:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/host", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"host_info:retrieve"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in GetPlatformInfo request", func() {
			It("Should not perform GetPlatformInfo - Invalid RequestHandler", func() {
				router.HandleFunc("/v2/host", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetPlatformInfo(negReqHandler, platformInfoFilePath), []string{"host_info:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/host", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"host_info:retrieve"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid Content-Type in GetPlatformInfo request", func() {
			It("Should not perform GetPlatformInfo - Invalid Content-Type", func() {
				router.HandleFunc("/v2/host", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetPlatformInfo(reqHandler, platformInfoFilePath), []string{"host_info:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/host", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"host_info:retrieve"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})

				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})
