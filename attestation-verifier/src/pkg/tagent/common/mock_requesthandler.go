/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"errors"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func NewMockRequestHandler(cfg *config.TrustAgentConfiguration) RequestHandler {
	return &MockRequestHandlerImpl{
		cfg: cfg,
	}
}

type MockRequestHandlerImpl struct {
	cfg *config.TrustAgentConfiguration
}

func (mrh *MockRequestHandlerImpl) GetTpmQuote(quoteRequest *taModel.TpmQuoteRequest, aikCertPath string, measureLogFilePath string, ramfsDir string) (*taModel.TpmQuoteResponse, error) {
	if mrh.cfg.Mode == "httptest" {
		return nil, errors.New("Failed to get TpmQuote")
	}
	return nil, nil
}

func (mrh *MockRequestHandlerImpl) GetHostInfo(string) (*taModel.HostInfo, error) {
	if mrh.cfg.Mode == "httptest" {
		return nil, errors.New("Failed to get hostinfo")
	}
	return nil, nil
}
func (mrh *MockRequestHandlerImpl) GetAikDerBytes(string) ([]byte, error) {
	if mrh.cfg.Mode == "httptest" {
		return nil, errors.New("Failed to get AikDerBytes")
	}
	return nil, nil
}
func (mrh *MockRequestHandlerImpl) DeployAssetTag(*taModel.TagWriteRequest) error {
	if mrh.cfg.Mode == "httptest" {
		return errors.New("Failed to perform DeployAssetTag")
	}
	return nil
}
func (mrh *MockRequestHandlerImpl) GetBindingCertificateDerBytes(bindingKeyCertificatePath string) ([]byte, error) {
	if mrh.cfg.Mode == "httptest" {
		return nil, errors.New("Failed to GetBindingCertificateDerBytes")
	}
	return nil, nil
}
func (mrh *MockRequestHandlerImpl) DeploySoftwareManifest(*taModel.Manifest, string) error {
	if mrh.cfg.Mode == "httptest" {
		return errors.New("Failed to perform DeploySoftwareManifest")
	}
	return nil
}
func (mrh *MockRequestHandlerImpl) GetApplicationMeasurement(*taModel.Manifest, string, string) (*taModel.Measurement, error) {
	if mrh.cfg.Mode == "httptest" {
		return nil, errors.New("Failed to GetApplicationMeasurement")
	}
	return nil, nil
}
