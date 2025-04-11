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

// Provide the same event logs in the manifest and to the PcrEventLogEquals rule, expecting
// no faults.
func TestPcrEventLogEqualsNoFault(t *testing.T) {
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

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, testHostManifestPcrEventLogEntry)
	rule, err := NewPcrEventLogEquals(&testHostManifestPcrEventLogEntry, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals rule verified")
}

// Provide the 'testExpectedPcrEventLogEntry' to the rule (it just contains to events)
// and a host manifest event log ('') that has component names that the excluding rule
// should ignore.
func TestPcrEventLogEqualsExcludingNoFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("Equals Excluding rule verified")
}

// Provide the empty pcr manifest values in the host manifest and when applying PcrEventLogEquals rule, expecting
// 'PcrManifestMissing' fault.
func TestEqualsExcludingPcrManifestMissingFault(t *testing.T) {
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
func TestPcrEventLogEqualsExcludingUnsupportedSHAFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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
	rule, err := NewPcrEventLogEqualsExcluding(&flavorEventsLog, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Create a host event log which has a mismatch field with the flavor event log
// which invokes 'mismatchfieldinformation' to the user.
func TestPcrEventLogEqualsExcludingMismatchFields(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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
	rule, err := NewPcrEventLogEqualsExcluding(&flavorEventsLog, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	assert.Equal(t, constants.PcrEventLogUnexpectedFields, result.MismatchField[0].Name)
	t.Logf("MismatchField description: %s", result.MismatchField[0].Description)
}

// Create a host event log that does not include the bank/index specified
// in the flavor event log to invoke a 'PcrEventLogMissing' fault.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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
	rule, err := NewPcrEventLogEqualsExcluding(&flavorEventsLog, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// create a copy of 'testExpectedEventLogEntries' and add new eventlog in the
// host manifest so that a PcrEventLogContainsUnexpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogContainsUnexpectedEntriesFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedPcrEventLogs := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: testHostManifestPcrEventLogEntry.Pcr.Index,
			Bank:  testHostManifestPcrEventLogEntry.Pcr.Bank,
		},
	}
	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, testHostManifestPcrEventLogEntry.TpmEvent...)
	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, hvs.EventLog{
		TypeName:    util.EVENT_LOG_DIGEST_SHA256,
		Measurement: "x",
	})

	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedPcrEventLogs)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogContainsUnexpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].UnexpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

// create a copy of 'testExpectedEventLogEntries' and remove an eventlog in the
// host manifest so that a PcrEventLogMissingExpectedEntries fault is raised.
func TestPcrEventLogEqualsExcludingPcrEventLogMissingExpectedEntriesFault(t *testing.T) {
	var excludetag = []string{"commandLine.", "LCP_CONTROL_HASH", "initrd", "vmlinuz", "componentName.imgdb.tgz", "componentName.onetime.tgz"}

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

	unexpectedPcrEventLogs := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: testHostManifestPcrEventLogEntry.Pcr.Index,
			Bank:  testHostManifestPcrEventLogEntry.Pcr.Bank,
		},
	}

	unexpectedPcrEventLogs.TpmEvent = append(unexpectedPcrEventLogs.TpmEvent, testHostManifestPcrEventLogEntry.TpmEvent[1:]...)
	hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs = append(hostManifest.PcrManifest.PcrEventLogMap.Sha256EventLogs, unexpectedPcrEventLogs)
	rule, err := NewPcrEventLogEqualsExcluding(&testExpectedPcrEventLogEntry, excludetag, uuid.New(), hvs.FlavorPartPlatform)
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
