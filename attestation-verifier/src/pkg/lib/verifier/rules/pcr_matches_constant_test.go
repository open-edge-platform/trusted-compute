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

func TestPcrMatchesConstantNoFault(t *testing.T) {
	expectedPcr := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: PCR_VALID_256,
	}

	hostManifest := hvs.HostManifest{
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_VALID_256,
					PcrBank: hvs.SHA256,
				},
			},
		},
	}

	rule, err := NewPcrMatchesConstant(&expectedPcr, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
	t.Logf("Pcr matches constant rule verified")
}

func TestPcrMatchesConstantNoMeasurementFault(t *testing.T) {
	expectedPcr := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
	}

	_, err := NewPcrMatchesConstant(&expectedPcr, hvs.FlavorPartPlatform)
	assert.Error(t, err)
}

func TestPcrMatchesConstantNoExpectedPcrFault(t *testing.T) {

	_, err := NewPcrMatchesConstant(nil, hvs.FlavorPartPlatform)
	assert.Error(t, err)
}

func TestPcrMatchesConstantPcrManifestMissingFault(t *testing.T) {
	expectedPcr := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: PCR_VALID_256,
	}

	rule, err := NewPcrMatchesConstant(&expectedPcr, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// provide a manifest without a PcrManifest and expect FaultPcrManifestMissing
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrManifestMissing)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrMatchesConstantMismatchFault(t *testing.T) {
	expectedPcr := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: PCR_VALID_256,
	}

	// host manifest with 'invalid' value for pcr0
	hostManifest := hvs.HostManifest{
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   0,
					Value:   PCR_INVALID_256,
					PcrBank: hvs.SHA256,
				},
			},
		},
	}

	rule, err := NewPcrMatchesConstant(&expectedPcr, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMismatchSHA256)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrMatchesConstantMissingFault(t *testing.T) {
	// empty manifest will result in 'missing' fault
	hostManifest := hvs.HostManifest{
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   1,
					Value:   PCR_VALID_256,
					PcrBank: hvs.SHA256,
				},
			},
		},
	}

	expectedPcr := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: PCR_VALID_256,
	}

	rule, err := NewPcrMatchesConstant(&expectedPcr, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMissing)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
