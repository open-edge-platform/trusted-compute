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

var _ = Describe("GetBindingKeyCertificate Request", func() {
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

	Describe("GetBindingKeyCertificate", func() {
		Context("GetBindingKeyCertificate request", func() {
			It("Should perform GetBindingKeyCertificate", func() {
				router.HandleFunc("/v2/binding-key-certificate", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetBindingKeyCertificate(reqHandler), []string{"binding_key:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/binding-key-certificate", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"binding_key:retrieve"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in GetBindingKeyCertificate request", func() {
			It("Should not perform GetBindingKeyCertificate - Invalid RequestHandler", func() {
				router.HandleFunc("/v2/binding-key-certificate", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetBindingKeyCertificate(negReqHandler), []string{"binding_key:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/binding-key-certificate", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"binding_key:retrieve"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})
		})

		Context("Invalid Content-Type in GetBindingKeyCertificate request", func() {
			It("Should not perform GetBindingKeyCertificate - Invalid Content-Type", func() {
				router.HandleFunc("/v2/binding-key-certificate", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetBindingKeyCertificate(reqHandler), []string{"binding_key:retrieve"}))).Methods(http.MethodGet)

				req, err := http.NewRequest(http.MethodGet, "/v2/binding-key-certificate", nil)
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"binding_key:retrieve"},
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
