/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/vmware"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"github.com/vmware/govmomi/vim25/mo"
	vim25Types "github.com/vmware/govmomi/vim25/types"
	"github.com/vmware/govmomi/vim25/xml"
)

func TestVmwareConnectorGetHostDetails(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	hostInfo := parseHostInfo(t)

	mockVMwareClient.On("GetHostInfo").Return(hostInfo, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	hostDetails, err := vmwareConnector.GetHostDetails()
	assert.NoError(t, err)
	assert.Equal(t, "VMware ESXi", hostDetails.OSName)
}

func TestVmwareConnectorGetHostDetailsError(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("GetHostInfo").Return(taModel.HostInfo{}, errors.New("sample error"))

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostDetails()
	assert.Error(t, err)
}

func TestVmwareConnectorGetHostManifest(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	hostInfo := parseHostInfo(t)
	mockVMwareClient.On("GetHostInfo").Return(hostInfo, nil)

	tpmAttestationReportResponse := parseTpmAttestationReportResponse(t)
	mockVMwareClient.On("GetTPMAttestationReport").Return(tpmAttestationReportResponse, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	hostManifest, err := vmwareConnector.GetHostManifest(nil)
	log.Info(hostManifest)
	assert.NoError(t, err)
	assert.Equal(t, "VMware ESXi", hostManifest.HostInfo.OSName)

	//Test error for invalid PCR number
	tpmAttestationReportResponse.Returnval.TpmPcrValues[0].PcrNumber = 24

	mockVMwareClient.On("GetTPMAttestationReport").Return(tpmAttestationReportResponse, nil)

	vmwareConnector = VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostManifest(nil)
	assert.Error(t, err)

	//Test error for invalid digest algorithm
	tpmAttestationReportResponse.Returnval.TpmPcrValues[0].PcrNumber = 0
	tpmAttestationReportResponse.Returnval.TpmPcrValues[0].DigestMethod = "MD5"

	mockVMwareClient.On("GetTPMAttestationReport").Return(tpmAttestationReportResponse, nil)

	vmwareConnector = VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostManifest(nil)
	assert.Error(t, err)
}

func TestVmwareConnectorGetHostManifestErrorHostInfo(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("GetHostInfo").Return(taModel.HostInfo{}, errors.New("sample error"))

	tpmAttestationReportResponse := parseTpmAttestationReportResponse(t)

	mockVMwareClient.On("GetTPMAttestationReport").
		Return(tpmAttestationReportResponse, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostManifest(nil)
	assert.Error(t, err)
}

func TestVmwareConnectorGetHostManifestErrorTpmReport(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	hostInfo := parseHostInfo(t)

	mockVMwareClient.On("GetHostInfo").Return(hostInfo, nil)

	var tpmAttestationReportResponse *vim25Types.QueryTpmAttestationReportResponse
	mockVMwareClient.On("GetTPMAttestationReport").
		Return(tpmAttestationReportResponse, errors.New("sample error"))

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostManifest(nil)
	assert.Error(t, err)
}

func TestVmwareConnectorGetHostManifestUnreliableTpmReport(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("GetHostInfo").Return(taModel.HostInfo{}, nil)

	hostAttestationReport := &vim25Types.HostTpmAttestationReport{TpmLogReliable: false}
	tpmAttestationReportResponse := &vim25Types.QueryTpmAttestationReportResponse{Returnval: hostAttestationReport}

	mockVMwareClient.On("GetTPMAttestationReport").
		Return(tpmAttestationReportResponse, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetHostManifest(nil)
	assert.Error(t, err)
}

func parseHostInfo(t *testing.T) taModel.HostInfo {
	var hostInfo taModel.HostInfo
	hostInfoBytes, err := ioutil.ReadFile("./test/sample_vmware_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(hostInfoBytes, &hostInfo)
	assert.NoError(t, err)
	return hostInfo
}

func parseTpmAttestationReportResponse(t *testing.T) *vim25Types.QueryTpmAttestationReportResponse {
	var tpmAttestationReportResponse *vim25Types.QueryTpmAttestationReportResponse

	file, err := os.Open("./test/sample_vmware_tpm_attestation_report.xml")
	assert.NoError(t, err)
	dec := xml.NewDecoder(file)
	dec.TypeFunc = vim25Types.TypeFunc()
	err = dec.Decode(&tpmAttestationReportResponse)
	assert.NoError(t, err)

	return tpmAttestationReportResponse
}

func TestGetClusterReferenceFault(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("GetVmwareClusterReference").Return([]mo.HostSystem{}, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	hostInfoList, err := vmwareConnector.GetClusterReference("")
	assert.NoError(t, err)
	assert.NotNil(t, hostInfoList)
}

func TestVmwareDeployAssetTag(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("DeployAssetTag").Return(nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	err = vmwareConnector.DeployAssetTag("068b5e88-1886-4ac2-a908-175cf723723f", "")
	assert.Error(t, err)
}

func TestVmwareDeploySoftwareManifest(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("DeploySoftwareManifest").Return(nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	err = vmwareConnector.DeploySoftwareManifest(taModel.Manifest{})
	assert.Error(t, err)
}

func TestVmwareGetMeasurementFromManifest(t *testing.T) {
	mockVMwareClient, err := vmware.NewMockVMWareClient()
	assert.NoError(t, err)

	mockVMwareClient.On("GetMeasurementFromManifest").Return(taModel.Measurement{}, nil)

	vmwareConnector := VmwareConnector{
		client: mockVMwareClient,
	}

	_, err = vmwareConnector.GetMeasurementFromManifest(taModel.Manifest{})
	assert.Error(t, err)
}
