/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"testing"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/stretchr/testify/assert"
)

func TestAssetTagMatchesNotProvisionedFault(t *testing.T) {

	hostManifest := hvs.HostManifest{
		AssetTagDigest: validAssetTagString, // valid tag in host
	}

	// provide a nil certificate value to the rule
	rule, err := NewAssetTagMatches(nil, assetTags)
	assert.NoError(t, err)

	// no faults should be returned...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultAssetTagNotProvisioned, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMissingFromManifest(t *testing.T) {

	hostManifest := hvs.HostManifest{
		AssetTagDigest: "", // not in host manifest
	}

	// simulate adding valid asset tag bytes from the flavor...
	rule, err := NewAssetTagMatches(validAssetTagBytes, assetTags)
	assert.NoError(t, err)

	// we should get a "missing asset tag" fault...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultAssetTagMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMismatch(t *testing.T) {

	hostManifest := hvs.HostManifest{
		AssetTagDigest: invalidAssetTagString, // in valid from the host
	}

	// simulate adding valid asset tag bytes from the flavor...
	rule, err := NewAssetTagMatches(validAssetTagBytes, assetTags)
	assert.NoError(t, err)

	// we should get a "asset tag mismatch" fault...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultAssetTagMismatch, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestAssetTagMatchesNoFault(t *testing.T) {

	hostManifest := hvs.HostManifest{
		AssetTagDigest: validAssetTagString, // valid tag in host
	}

	// simulate adding valid asset tag bytes from the flavor...
	rule, err := NewAssetTagMatches(validAssetTagBytes, assetTags)
	assert.NoError(t, err)

	// no faults should be returned...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
}
