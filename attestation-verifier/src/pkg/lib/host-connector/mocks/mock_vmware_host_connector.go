/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/vmware"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/mock"
	"github.com/vmware/govmomi/vim25/mo"
)

type MockVmwareConnector struct {
	client *vmware.MockVMWareClient
	mock.Mock
}

func (vhc *MockVmwareConnector) GetTPMQuoteResponse(nonce string, pcrList []int) ([]byte, []byte, *x509.Certificate, *pem.Block, taModel.TpmQuoteResponse, error) {
	args := vhc.Called(nonce, pcrList)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Get(2).(*x509.Certificate), args.Get(3).(*pem.Block), args.Get(4).(taModel.TpmQuoteResponse), args.Error(1)
}

func (vhc *MockVmwareConnector) GetHostDetails() (taModel.HostInfo, error) {
	args := vhc.Called()
	return args.Get(0).(taModel.HostInfo), args.Error(1)
}

func (vhc *MockVmwareConnector) GetHostManifest([]int) (hvs.HostManifest, error) {
	args := vhc.Called()
	return args.Get(0).(hvs.HostManifest), args.Error(1)
}

func (vhc *MockVmwareConnector) DeployAssetTag(hardwareUUID, tag string) error {
	args := vhc.Called(hardwareUUID, tag)
	return args.Error(0)
}

func (vhc *MockVmwareConnector) DeploySoftwareManifest(manifest taModel.Manifest) error {
	args := vhc.Called(manifest)
	return args.Error(0)
}

func (vhc *MockVmwareConnector) GetMeasurementFromManifest(manifest taModel.Manifest) (taModel.Measurement, error) {
	args := vhc.Called(manifest)
	return args.Get(0).(taModel.Measurement), args.Error(1)
}

func (vhc *MockVmwareConnector) GetClusterReference(clusterName string) ([]mo.HostSystem, error) {
	args := vhc.Called(clusterName)
	return args.Get(0).([]mo.HostSystem), args.Error(1)
}
