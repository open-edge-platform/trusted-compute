/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerImageFlavorCreation(t *testing.T) {

	//flavor with encryption enabled and integrity enforced
	flavorInput, err := GetContainerImageFlavor("docker.registry.com:5000/hello-world:encrypted", true,
		"http://kbs.server.com:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", true, "https://docker.notary.com:4443")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)

	//Flavor with only integrity enforced
	flavorInput, err = GetContainerImageFlavor("docker.registry.com:5000/hello-world:signed", false, "",
		true, "https://docker.notary.com:4443")
	assert.NoError(t, err)
	flavor, err = json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)

	//Flavor with only encryption
	flavorInput, err = GetContainerImageFlavor("docker.registry.com:5000/hello-world:encrypted", true,
		"http://kbs.server.com:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer", false, "")
	assert.NoError(t, err)
	flavor, err = json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)

	//Flavor with no encryption and integrity enforced
	flavorInput, err = GetContainerImageFlavor("hello-world", false, "", false, "")
	assert.NoError(t, err)
	flavor, err = json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)
}

// TestImageFlavorWithEmptyLabel verifies error on empty label
func TestImageFlavorWithEmptyLabel(t *testing.T) {
	//Flavor with only integrity enforced
	flavorInput, err := GetContainerImageFlavor("", false, "",
		true, "https://docker.notary.com:4443")
	assert.Error(t, err)
	assert.Nil(t, flavorInput)
}

func TestContainerImageFlavorCreationFail_InvalidLabel(t *testing.T) {
	//Flavor with only integrity enforced
	flavorInput, err := GetContainerImageFlavor("", false, "",
		true, "https://docker.notary.com:4443")
	assert.Error(t, err)
	assert.Nil(t, flavorInput)
}
