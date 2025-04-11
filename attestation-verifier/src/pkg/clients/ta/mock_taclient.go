/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package ta

//go:generate mockgen -destination=mock_taclient.go -package=ta github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/clients/ta TAClient

import (
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"net/url"
)

type MockTAClient struct {
	mock.Mock
}

func NewMockTAClient() (*MockTAClient, error) {
	mockTAClient := MockTAClient{}
	return &mockTAClient, nil
}

func (ta *MockTAClient) GetHostInfo() (taModel.HostInfo, error) {
	args := ta.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (ta *MockTAClient) GetTPMQuote(nonce string, pcrList []int, pcrBankList []string) (taModel.TpmQuoteResponse, error) {
	args := ta.Called(nonce, pcrList, pcrBankList)
	return args.Get(0).(taModel.TpmQuoteResponse), args.Error(1)
}

func (ta *MockTAClient) GetAIK() ([]byte, error) {
	args := ta.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (ta *MockTAClient) GetBindingKeyCertificate() ([]byte, error) {
	args := ta.Called()
	return args.Get(0).([]byte), args.Error(1)
}

func (ta *MockTAClient) DeployAssetTag(hardwareUUID, tag string) error {
	args := ta.Called(hardwareUUID, tag)
	return args.Error(0)
}

func (ta *MockTAClient) DeploySoftwareManifest(manifest taModel.Manifest) error {
	args := ta.Called(manifest)
	return args.Error(0)
}

func (ta *MockTAClient) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	args := ta.Called(manifest)
	return args.Get(0).(taModel.Measurement), args.Error(1)
}

func (ta *MockTAClient) GetBaseURL() *url.URL {
	args := ta.Called()
	return args.Get(0).(*url.URL)
}
