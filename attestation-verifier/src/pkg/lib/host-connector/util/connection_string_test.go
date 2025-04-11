/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetConnectorDetails(t *testing.T) {
	sampleUrl1 := "intel:https://ta.ip.com:1443;u=admin;p=password"
	sampleUrl2 := "https://ta.ip.com:1443;u=admin;p=password"
	sampleUrl3 := "vmware:https://vsphere.com:443/sdk;h=hostName;u=admin.local;p=password"
	sampleUrl4 := "https://vsphere.com:443/sdk;h=hostName;u=admin.local;p=password"
	sampleUrl5 := "microsoft:https://microsoft.com:1443;u=admin.local;p=password"

	invalidUrl := "https:// abcde"

	connectorDetails, err := GetConnectorDetails(sampleUrl1)
	assert.NoError(t, err)
	assert.Equal(t, constants.VendorIntel, connectorDetails.Vendor)

	connectorDetails, err = GetConnectorDetails(sampleUrl2)
	assert.NoError(t, err)
	assert.Equal(t, constants.VendorIntel, connectorDetails.Vendor)

	connectorDetails, err = GetConnectorDetails(sampleUrl3)
	assert.NoError(t, err)
	assert.Equal(t, constants.VendorVMware, connectorDetails.Vendor)

	connectorDetails, err = GetConnectorDetails(sampleUrl4)
	assert.NoError(t, err)
	assert.Equal(t, constants.VendorVMware, connectorDetails.Vendor)

	connectorDetails, err = GetConnectorDetails(sampleUrl5)
	assert.NoError(t, err)
	assert.Equal(t, constants.VendorMicrosoft, connectorDetails.Vendor)

	connectorDetails, err = GetConnectorDetails(invalidUrl)
	assert.Error(t, err)
}

func TestParseConnectionString(t *testing.T) {
	sampleUrl1 := "vmware:https://vsphere.com:portNo/sdk;h=hostName;u=admin.local;p=password"

	url, userName, password, hostName := ParseConnectionString(sampleUrl1)
	assert.Equal(t, url, "vmware:https://vsphere.com:portNo/sdk")
	assert.Equal(t, userName, "admin.local")
	assert.Equal(t, password, "password")
	assert.Equal(t, hostName, "hostName")
}
