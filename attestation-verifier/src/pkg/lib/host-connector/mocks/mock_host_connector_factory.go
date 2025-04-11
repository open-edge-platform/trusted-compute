/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"io/ioutil"
	"os"

	host_connector "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/mock"
	"github.com/vmware/govmomi/vim25/mo"
	vim25Types "github.com/vmware/govmomi/vim25/types"
)

// MockHostConnectorFactory is required for mocking the HostConnector dependency in flows involving HostConnector
// using MockedHostConnector in its place
type MockHostConnectorFactory struct{}

// NewHostConnector returns a mocked instance of VendorConnector passing in a MockedTAClient or a MockVMwareClient as required
func (htcFactory MockHostConnectorFactory) NewHostConnector(connectionString string) (host_connector.HostConnector, error) {
	vendorConnector, _ := util.GetConnectorDetails(connectionString)
	var connectorFactory host_connector.VendorHostConnectorFactory
	switch vendorConnector.Vendor {
	case constants.VendorIntel, constants.VendorMicrosoft:
		connectorFactory = &MockIntelConnectorFactory{}
	case constants.VendorVMware:
		connectorFactory = &MockVmwareConnectorFactory{}
	default:
		return nil, errors.New("mock_host_connector_factory:NewHostConnector() Vendor not supported yet: " + vendorConnector.Vendor.String())
	}
	return connectorFactory.GetHostConnector(vendorConnector, "", nil, true)
}

// MockIntelConnectorFactory implements the VendorConnectorFactory interface
type MockIntelConnectorFactory struct{}

// GetHostConnector returns an instance of IntelConnector passing in a MockedTAClient
func (micf MockIntelConnectorFactory) GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate, imaMeasureEnabled bool) (host_connector.HostConnector, error) {
	mhc := MockIntelConnector{}

	// AnythingOfType allows us to wildcard the digest hash since this will be computed at runtime
	mhc.On("DeployAssetTag", "7a569dad-2d82-49e4-9156-069b0065b262", mock.AnythingOfType("string")).Return(nil)
	mhc.On("DeployAssetTag", "00e4d709-8d72-44c3-89ae-c5edc395d6fe", mock.AnythingOfType("string")).Return(errors.New("Error deploying tag"))

	// Mock GetHostDetails
	var hostInfo taModel.HostInfo
	hostInfoJson, _ := os.Open("../../lib/host-connector/test/sample_platform_info.json")
	hostInfoBytes, _ := ioutil.ReadAll(hostInfoJson)
	_ = json.Unmarshal(hostInfoBytes, &hostInfo)
	mhc.On("GetHostDetails").Return(hostInfo, nil)

	// Mock GetHostManifest
	var hm hvs.HostManifest
	hmBytes, _ := ioutil.ReadFile("../../lib/host-connector/test/sample_host_manifest.json")
	_ = json.Unmarshal(hmBytes, &hm)
	mhc.On("GetHostManifest").Return(hm, nil)

	var measurement taModel.Measurement
	_ = xml.Unmarshal([]byte("<Measurement DigestAlg=\"SHA384\" Label=\"ISL_Applications123\">"+
		"<File xmlns=\"lib:wml:measurements:1.0\" Path=\"/opt/trustagent/bin/module_analysis_da.sh\">2a99c3e80e99d495a"+
		"6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File><Dir xmlns=\"lib:wml:"+
		"measurements:1.0\" Include=\".*\" Path=\"/opt/trustagent/bin\">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337"+
		"daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir><CumulativeHash xmlns=\"lib:wml:measurements:1.0\">be"+
		"7c2c93d8fd084a6b5ba0b4641f02315bde361202b36c4b88eefefa6928a2c17ac0e65ec6aeb930220cf079e46bcb9f</CumulativeHash>"+
		"</Measurement>"), &measurement)
	mhc.On("GetMeasurementFromManifest", mock.Anything).Return(measurement, nil)

	mhc.On("DeploySoftwareManifest", mock.Anything).Return(nil)

	return &mhc, nil
}

// MockVmwareConnectorFactory implements the VendorConnectorFactory interface
type MockVmwareConnectorFactory struct{}

// GetHostConnector returns an instance of VmwareConnector passing in a MockVMwareClient
func (micf MockVmwareConnectorFactory) GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate, imaMeasureEnabled bool) (host_connector.HostConnector, error) {
	vmc := MockVmwareConnector{}

	var hostInfoList []mo.HostSystem
	hostInfoList = append(hostInfoList, mo.HostSystem{ManagedEntity: mo.ManagedEntity{Name: "1.1.1.1"}, Summary: vim25Types.HostListSummary{Hardware: &vim25Types.HostHardwareSummary{Uuid: "7a569dad-2d82-49e4-9156-069b0065b261"}}})
	hostInfoList = append(hostInfoList, mo.HostSystem{ManagedEntity: mo.ManagedEntity{Name: "2.2.2.2"}, Summary: vim25Types.HostListSummary{Hardware: &vim25Types.HostHardwareSummary{Uuid: "7a569dad-2d82-49e4-9156-069b0065b262"}}})
	vmc.On("GetClusterReference", mock.AnythingOfType("string")).Return(hostInfoList, nil)

	var hostInfo taModel.HostInfo
	hostInfoJson, _ := ioutil.ReadFile("./test/sample_vmware_platform_info.json")
	_ = json.Unmarshal(hostInfoJson, &hostInfo)
	vmc.On("GetHostDetails").Return(hostInfo, nil)

	return &vmc, nil
}
