/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"testing"

	"github.com/google/uuid"
	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/stretchr/testify/assert"
)

// Create an event log that is used by the hostManifest and the rule,
// expecting that they match and will not generate any faults.
func TestPcrEventLogIncludesNoFault(t *testing.T) {
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testExpectedPcrEventLogEntry)
	rule, err := NewPcrEventLogIncludes(&testExpectedPcrEventLogEntry, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Includes rule verified")
}

// Create an event log that is used by the hostManifest and the rule,
// expecting that they match and will not generate any faults.
func TestPcrEventLogIncludesFault(t *testing.T) {

	_, err := NewPcrEventLogIncludes(nil, hvs.FlavorPartPlatform)
	assert.Error(t, err)
}

// Provide the empty pcr manifest values in the host manifest and when applying PcrEventLogEquals rule, expecting
// 'PcrManifestMissing' fault.
func TestIncludesPcrManifestMissingFault(t *testing.T) {
	hostManifest := hvs.HostManifest{
		PcrManifest: hvs.PcrManifest{},
	}

	rule, err := NewPcrEventLogEquals(&testHostManifestPcrEventLogEntry, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrManifestMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Provide unsupported SHA algorithm
func TestPcrEventLogIncludesUnsupportedSHAFault(t *testing.T) {
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

	flavorEventsLog := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA512",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
		},
	}

	hostEventsLog := hvs.TpmEventLog{
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Create a host event log which has a mismatch field with the flavor event log
// which invokes 'mismatchfieldinformation' to the user.
func TestPcrEventLogIncludesMismatchFields(t *testing.T) {

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

	flavorEventsLog := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA1,
				Measurement: zeros,
			},
		},
	}

	hostEventsLog := hvs.TpmEventLog{
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	assert.Equal(t, constants.PcrEventLogMissingFields, result.MismatchField[0].Name)
	t.Logf("MismatchField description: %s", result.MismatchField[0].Description)
}

// Create an event log for the rule with two measurements and only provide
// one to the host manifest.  Expect a 'FaultPcrEventlogMissingExpectedEntries'
// fault.
func TestPcrEventLogIncludesMissingMeasurement(t *testing.T) {
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

	flavorEventsLog := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostEventsLog := hvs.TpmEventLog{
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	assert.Equal(t, 1, len(result.Faults[0].MissingEntries))
	assert.Equal(t, ones, result.Faults[0].MissingEntries[0].Measurement)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create flavor/host events that use the same bank/index but
// different measurement to nvoke the 'PcrEventlogMissingExpectedEntries'
// fault.
func TestPcrEventLogIncludesDifferentMeasurement(t *testing.T) {
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

	flavorEventsLog := hvs.TpmEventLog{
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

	// host manifest has 'ones' for the measurement (not 'zeros')
	hostEventsLog := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	assert.Equal(t, 1, len(result.Faults[0].MissingEntries))
	assert.Equal(t, zeros, result.Faults[0].MissingEntries[0].Measurement)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogIncludesPcrEventLogMissingFault(t *testing.T) {
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

	flavorEventsLog := hvs.TpmEventLog{
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

	// Put something in PCR1 (not PCR0) to invoke PcrMissingEventLog fault
	hostEventsLog := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 1,
			Bank:  "SHA256",
		},
		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, hostEventsLog)
	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// Create a host event log that without an event log to invoke a
// 'PcrEventLogMissing' fault.
func TestPcrEventLogIncludesNoEventLogInHostManifest(t *testing.T) {
	// Create a HostManifest without any event logs to invoke PcrEventLogMissing fault.
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

	flavorEventsLog := hvs.TpmEventLog{
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

	rule, err := NewPcrEventLogIncludes(&flavorEventsLog, hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
