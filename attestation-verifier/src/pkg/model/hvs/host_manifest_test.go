/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostManifestParsing(t *testing.T) {

	var hostManifest HostManifest
	readBytes, err := ioutil.ReadFile("../../lib/host-connector/test/sample_host_manifest.json")
	assert.NoError(t, err)
	err = json.Unmarshal(readBytes, &hostManifest)
	assert.NoError(t, err)

	aik, err := hostManifest.GetAIKCertificate()
	assert.NoError(t, err)
	assert.NotEqual(t, aik, nil)

	//test for invalid base64 encoding in AIK certificate
	hostManifest.AIKCertificate = "abcde"
	aik, err = hostManifest.GetAIKCertificate()
	assert.Error(t, err)

	//test for invalid AIK certificate
	hostManifest.AIKCertificate = "YWJjZGU="
	aik, err = hostManifest.GetAIKCertificate()
	assert.Error(t, err)

	//test for invalid manifest
	hostManifest = HostManifest{}
	invalidManifest := "abcde"
	err = json.Unmarshal([]byte(invalidManifest), &hostManifest)
	assert.Error(t, err)

	aik, err = hostManifest.GetAIKCertificate()
	assert.Error(t, err)
}
