/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package host_connector

import (
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"io/ioutil"
	"net/url"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/ta"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetHostDetails(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)
	var hostInfo taModel.HostInfo
	hostInfoJson, err := ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(hostInfoJson, &hostInfo)
	assert.NoError(t, err)

	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	hostInfo, err = intelConnector.GetHostDetails()
	assert.NoError(t, err)
	assert.Equal(t, "RedHatEnterprise", hostInfo.OSName)
	assert.Equal(t, "Intel Corporation", hostInfo.BiosName)
}

func TestCreateHostManifestFromSampleData(t *testing.T) {

	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()

	// read sample tpm quote that will be returned by the mock client
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("./test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)
	mockTAClient.On("GetTPMQuote", mock.Anything, mock.Anything, mock.Anything).Return(tpmQuoteResponse, nil)

	// read sample platform-info that will be returned my the mock client
	var hostInfo taModel.HostInfo
	b, err = ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(b, &hostInfo)
	assert.NoError(t, err)
	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)

	// read the aik that will be returned by the mock
	aikBytes, err := ioutil.ReadFile("./test/aik.pem")
	aikDer, _ := pem.Decode(aikBytes)
	assert.NoError(t, err)
	mockTAClient.On("GetAIK").Return(aikDer.Bytes, nil)

	// the sample data in ./test was collected from 168.63 -- this is needed
	// for the nonce to verify...
	baseUrl, err := url.Parse("http://127.0.0.1:1443/")
	assert.NoError(t, err)
	mockTAClient.On("GetBaseURL").Return(baseUrl, nil)

	// binding key is only applicable to workload-agent (skip for now)
	mockTAClient.On("GetBindingKeyCertificate").Return([]byte{}, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	// the sample data in ./test used this nonce which needs to be provided to GetHostManifest...
	nonce := "EsJ0GRgwSvwn9u3ir9NhidLSKVX5oVn2UJKsH4heHuQ="

	hostManifest, err := intelConnector.GetHostManifestAcceptNonce(nonce, nil)
	assert.NoError(t, err)

	json, err := json.Marshal(hostManifest)
	assert.NoError(t, err)
	t.Log(string(json))
}

func TestEventReplay256(t *testing.T) {
	// this data was extracted from an existing host manifest...
	eventLogJson := `
	{
		"pcr": {
			"index": 18,
			"bank": "SHA256"
		},
		"tpm_events": [
			{
				"type_id": "0x40c",
				"type_name": "LCP_CONTROL_HASH",
				"tags": [
					"LCP_CONTROL_HASH"
				],
				"measurement": "df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119"
			},
			{
				"type_id": "0x501",
				"type_name": "initrd",
				"tags": [
					"initrd"
				],
				"measurement": "22cfecd21f4de210d16829f786719798a351a5554bfc659911064d85e60ebade"
			}
		]
	 }`

	pcr18json := `
	{
		"pcr": {
			"index": 18,
			"bank": "SHA256"
		},
		"measurement": "f35c6f35fd9e16354494f842ebf9f88842a4bf84df059eaf2909e93de90354aa",
		"pcr_matches": true
	}`

	var eventLogEntry hvs.TpmEventLog
	var pcr18 hvs.FlavorPcrs

	assert.NoError(t, json.Unmarshal([]byte(eventLogJson), &eventLogEntry))
	assert.NoError(t, json.Unmarshal([]byte(pcr18json), &pcr18))

	cumulativeHash, err := eventLogEntry.Replay()
	assert.NoError(t, err)
	assert.Equal(t, pcr18.Measurement, cumulativeHash)
}

func TestGetMeasurementFromManifest(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	var manifest taModel.Manifest
	var measurement taModel.Measurement

	manifestXml, err := ioutil.ReadFile("./test/sample_manifest.xml")
	assert.NoError(t, err)

	err = xml.Unmarshal(manifestXml, &manifest)
	assert.NoError(t, err)

	measurementXml, err := ioutil.ReadFile("./test/sample_measurement.xml")
	err = xml.Unmarshal(measurementXml, &measurement)
	assert.NoError(t, err)
	mockTAClient.On("GetMeasurementFromManifest", manifest).Return(measurement, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	measurementResponse, err := intelConnector.GetMeasurementFromManifest(manifest)
	assert.NoError(t, err)
	log.Info("Measurement is : ", measurementResponse)
}

func TestDeployAssetTag(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)

	hardwareUUID := "7a569dad-2d82-49e4-9156-069b0065b262"
	tag := "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k="

	mockTAClient.On("DeployAssetTag", hardwareUUID, tag).Return(nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	err = intelConnector.DeployAssetTag(hardwareUUID, tag)
	assert.NoError(t, err)
}

func TestDeploySoftwareManifest(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()
	assert.NoError(t, err)

	var manifest taModel.Manifest

	manifestXml, err := ioutil.ReadFile("./test/sample_manifest.xml")
	assert.NoError(t, err)

	err = xml.Unmarshal(manifestXml, &manifest)
	assert.NoError(t, err)

	mockTAClient.On("DeploySoftwareManifest", manifest).Return(nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	err = intelConnector.DeploySoftwareManifest(manifest)
	assert.NoError(t, err)
}

func TestGetHostManifest(t *testing.T) {
	// create a mock ta client that will return dummy data to host-connector
	mockTAClient, err := ta.NewMockTAClient()

	// read sample tpm quote that will be returned by the mock client
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("./test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)
	mockTAClient.On("GetTPMQuote", mock.Anything, mock.Anything, mock.Anything).Return(tpmQuoteResponse, nil)

	// read sample platform-info that will be returned my the mock client
	var hostInfo taModel.HostInfo
	b, err = ioutil.ReadFile("./test/sample_platform_info.json")
	assert.NoError(t, err)
	err = json.Unmarshal(b, &hostInfo)
	assert.NoError(t, err)
	mockTAClient.On("GetHostInfo").Return(hostInfo, nil)

	// read the aik that will be returned by the mock
	aikBytes, err := ioutil.ReadFile("./test/aik.pem")
	aikDer, _ := pem.Decode(aikBytes)
	assert.NoError(t, err)
	mockTAClient.On("GetAIK").Return(aikDer.Bytes, nil)

	// the sample data in ./test was collected from 168.63 -- this is needed
	// for the nonce to verify...
	baseUrl, err := url.Parse("http://127.0.0.1:1443/")
	assert.NoError(t, err)
	mockTAClient.On("GetBaseURL").Return(baseUrl, nil)

	// binding key is only applicable to workload-agent (skip for now)
	mockTAClient.On("GetBindingKeyCertificate").Return([]byte{}, nil)

	// create an intel host connector and collect the manifest
	intelConnector := IntelConnector{
		client: mockTAClient,
	}

	_, err = intelConnector.GetHostManifest(nil)
	assert.Error(t, err)
}
