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
	"strings"
)

var _ = Describe("GetTpmQuote Request", func() {
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

	Describe("GetTpmQuote", func() {
		Context("GetTpmQuote request", func() {
			It("Should perform GetTpmQuote", func() {
				router.HandleFunc("/v2/tpm/quote", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetTpmQuote(reqHandler), []string{"quote:create"}))).Methods(http.MethodPost)

				tpmQuoteReq := `{ 
					"nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", 
					"pcrs": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23] , 
					"pcrbanks" : ["SHA1", "SHA256"]
				}`

				req, err := http.NewRequest(http.MethodPost, "/v2/tpm/quote", strings.NewReader(tpmQuoteReq))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"quote:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})

				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusOK))
			})
		})

		Context("Invalid RequestHandler in GetTpmQuote request", func() {
			It("Should not perform GetTpmQuote", func() {
				router.HandleFunc("/v2/tpm/quote", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
					controllers.GetTpmQuote(negReqHandler), []string{"quote:create"}))).Methods(http.MethodPost)

				tpmQuoteReq := `{ 
					"nonce":"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", 
					"pcrs": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23] , 
					"pcrbanks" : ["SHA1", "SHA256"]
				}`

				req, err := http.NewRequest(http.MethodPost, "/v2/tpm/quote", strings.NewReader(tpmQuoteReq))
				Expect(err).NotTo(HaveOccurred())

				permissions := ct.PermissionInfo{
					Service: constants.TAServiceName,
					Rules:   []string{"quote:create"},
				}
				req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})

				req.Header.Set("Content-Type", consts.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusInternalServerError))
			})

			Context("Invalid Content-Type in GetTpmQuote request", func() {
				It("Should not perform GetTpmQuote - Invalid Content-Type", func() {
					router.HandleFunc("/v2/tpm/quote", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
						controllers.GetTpmQuote(reqHandler), []string{"quote:create"}))).Methods(http.MethodPost)

					req, err := http.NewRequest(http.MethodPost, "/v2/tpm/quote", nil)
					Expect(err).NotTo(HaveOccurred())

					permissions := ct.PermissionInfo{
						Service: constants.TAServiceName,
						Rules:   []string{"quote:create"},
					}
					req = context.SetUserPermissions(req, []ct.PermissionInfo{permissions})
					w = httptest.NewRecorder()
					router.ServeHTTP(w, req)
					Expect(w.Code).To(Equal(http.StatusBadRequest))
				})
			})

			Context("Invalid Request Body in GetTpmQuote request", func() {
				It("Should not perform GetTpmQuote - Invalid Request Body", func() {
					router.HandleFunc("/v2/tpm/quote", tagentRouter.ErrorHandler(tagentRouter.RequiresPermission(
						controllers.GetTpmQuote(negReqHandler), []string{"quote:create"}))).Methods(http.MethodPost)

					tpmQuoteReq := `{ 
					"nonce:"ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=", 
					"pcrs: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23] , 
					"pcrbanks" : ["SHA1", "SHA256"]
				}`

					req, err := http.NewRequest(http.MethodPost, "/v2/tpm/quote", strings.NewReader(tpmQuoteReq))
					Expect(err).NotTo(HaveOccurred())

					permissions := ct.PermissionInfo{
						Service: constants.TAServiceName,
						Rules:   []string{"quote:create"},
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
})
