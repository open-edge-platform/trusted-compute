/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hosttrust

import (
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHostManifestMap(t *testing.T) {
	var hm *hvs.HostManifest
	data, err := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	assert.NoError(t, err)

	err = json.Unmarshal(data, &hm)
	assert.NoError(t, err)

	flavorParts := []hvs.FlavorPartName{hvs.FlavorPartHostUnique, hvs.FlavorPartPlatform, hvs.FlavorPartOs, hvs.FlavorPartAssetTag, hvs.FlavorPartSoftware}
	hostManifestMap, err := getHostManifestMap(hm, flavorParts)
	assert.NoError(t, err)
	assert.NotNil(t, hostManifestMap)
}

func TestGetMeasurementLabels(t *testing.T) {
	var hm *hvs.HostManifest
	data, err := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	assert.NoError(t, err)

	err = json.Unmarshal(data, &hm)
	assert.NoError(t, err)
	softwareLabels, err := getMeasurementLabels(hm)
	assert.NoError(t, err)
	assert.Equal(t, []string{"ISecL_Default_Application_Flavor_v3.3_TPM2.0", "ISecL_Default_Workload_Flavor_v3.3"}, softwareLabels)
}
