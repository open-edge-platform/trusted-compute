/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"testing"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/stretchr/testify/assert"
)

func TestPcrEventLogIntegrityNoFault(t *testing.T) {
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: expectedCumulativeHash,
	}

	expectedPcrLog1 := hvs.HostManifestPcrs{
		Index:   0,
		PcrBank: "SHA256",
		Value:   expectedCumulativeHash,
	}

	hostManifest := hvs.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcrLog1)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Integrity rule verified")
}

func TestPcrEventLogIntegrityFault(t *testing.T) {

	_, err := NewPcrEventLogIntegrity(nil, hvs.FlavorPartPlatform)
	assert.Error(t, err)
}

// Provide the empty pcr manifest values in the host manifest and when applying PcrEventLogEquals rule, expecting
// 'PcrManifestMissing' fault.
func TestIntegrityPcrManifestMissingFault(t *testing.T) {
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: expectedCumulativeHash,
	}

	hostManifest := hvs.HostManifest{
		PcrManifest: hvs.PcrManifest{},
	}

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrManifestMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Provide unsupported SHA algorithm
func TestPcrEventLogIntegrityUnsupportedSHAFault(t *testing.T) {
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA512",
		},
		Measurement: expectedCumulativeHash,
	}

	expectedPcrLog1 := hvs.HostManifestPcrs{
		Index:   0,
		PcrBank: "SHA256",
		Value:   expectedCumulativeHash,
	}

	hostManifest := hvs.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcrLog1)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestPcrEventLogIntegrityPcrValueMissingFault(t *testing.T) {
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

	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: expectedCumulativeHash,
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)

	// if the pcr is no incuded, the PcrEventLogIntegrity rule should return
	// a PcrMissingFault
	// hostManifest.PcrManifest.Sha256Pcrs = ...not set
	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrValueMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, hvs.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrEventLogIntegrityPcrEventLogMissingFault(t *testing.T) {
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog1 := hvs.HostManifestPcrs{
		Index:   hvs.PCR0,
		PcrBank: hvs.SHA256,
		Value:   expectedCumulativeHash,
	}
	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: expectedCumulativeHash,
	}

	hostManifest := hvs.HostManifest{}
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, expectedPcrLog1)
	// omit the event log from the host manifest to invoke "PcrEventLogMissing" fault...
	//hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, eventLogEntry)
	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, hvs.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestPcrEventLogIntegrityPcrEventLogInvalidFault(t *testing.T) {
	expectedCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	expectedPcrLog := hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		Measurement: expectedCumulativeHash,
	}

	invalidPcrEventLogEntry := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	invalidCumulativeHash, err := testExpectedPcrEventLogEntry.Replay()
	assert.NoError(t, err)

	invalidPcrLog := hvs.HostManifestPcrs{
		Index:   hvs.PCR0,
		PcrBank: hvs.SHA256,
		Value:   invalidCumulativeHash,
	}

	hostManifest := hvs.HostManifest{}
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, invalidPcrEventLogEntry)
	hostManifest.PcrManifest.Sha256Pcrs = append(hostManifest.PcrManifest.Sha256Pcrs, invalidPcrLog)

	rule, err := NewPcrEventLogIntegrity(&expectedPcrLog, hvs.FlavorPartPlatform)

	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogInvalid, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].PcrIndex) // should report the missing pcr
	assert.Equal(t, hvs.PCR0, *result.Faults[0].PcrIndex)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
