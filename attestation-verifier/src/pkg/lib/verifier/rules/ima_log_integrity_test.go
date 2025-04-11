/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"testing"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
)

//TestImaLogIntegrityNoFault checks the no fault
func TestImaLogIntegrityNoFault(t *testing.T) {
	expectedImaLogs := &hvs.Ima{
		Measurements: []hvs.Measurements{
			{
				File:        "boot_aggregate",
				Measurement: "a9ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
			},
			{
				File:        "/root/testFiles1/testfile2.txt",
				Measurement: "510bf52b8637f1c58a4840b955a86041133e3fb3770cae4ca97c06df9685cbad",
			},
			{
				File:        "/root/testFiles1/testfile1.txt",
				Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
			},
		},
	}

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	hostManifest := &hvs.HostManifest{
		HostInfo: model.HostInfo{
			HardwareUUID: "8dbf926c-04d2-03e2-b211-d21d00db521a",
		},
		ImaLogs: &hvs.ImaLogs{
			Pcr: hvs.Pcr{
				Index: 10,
				Bank:  "SHA256",
			},
			ImaTemplate: "ima-ng",
			Measurements: []hvs.Measurements{
				{
					File:        "boot_aggregate",
					Measurement: "a9ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "510bf52b8637f1c58a4840b955a86041133e3fb3770cae4ca97c06df9685cbad",
				},
				{
					File:        "/root/testFiles1/testfile1.txt",
					Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
				},
			},
		},
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   10,
					Value:   "931960a61a97081091daeb546cbfd30d9e8fd72c2e6f9f1e6480278223c52d81",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, len(result.Faults))
	t.Logf("IMA log integrity rule verified")
}

//TestImaLogIntegrityImaLogsMissingFault checks the ima log missing in host manifest fault
func TestImaLogIntegrityImaLogsMissingFault(t *testing.T) {
	expectedImaLogs := &hvs.Ima{
		Measurements: []hvs.Measurements{
			{
				File:        "boot_aggregate",
				Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
			},
			{
				File:        "/root/testFiles1/testfile2.txt",
				Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
			},
			{
				File:        "/root/testFiles1/testfile1.txt",
				Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fd8066de",
			},
		},
	}

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	hostManifest := &hvs.HostManifest{
		HostInfo: model.HostInfo{
			HardwareUUID: "8dbf926c-04d2-03e2-b211-d21d00db521a",
		},
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   10,
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)
	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(result.Faults))
}

//TestImaLogIntegrityImaLogInvalidFault checks the calculated cumulative hash mismatch fault
func TestImaLogIntegrityImaLogInvalidFault(t *testing.T) {
	expectedImaLogs := &hvs.Ima{
		Measurements: []hvs.Measurements{
			{
				File:        "boot_aggregate",
				Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
			},
			{
				File:        "/root/testFiles1/testfile2.txt",
				Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
			},
			{
				File:        "/root/testFiles1/testfile1.txt",
				Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fd8066de",
			},
		},
	}

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	hostManifest := &hvs.HostManifest{
		HostInfo: model.HostInfo{
			HardwareUUID: "8dbf926c-04d2-03e2-b211-d21d00db521a",
		},
		ImaLogs: &hvs.ImaLogs{
			Pcr: hvs.Pcr{
				Index: 10,
				Bank:  "SHA256",
			},
			ImaTemplate: "ima-ng",
			Measurements: []hvs.Measurements{
				{
					File:        "boot_aggregate",
					Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
				},
				{
					File:        "/root/testFiles1/testfile1.txt",
					Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fdaab50a",
				},
			},
		},
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   10,
					Value:   "cf0460a7561c4cb28be0e95628613cf3539f8c3ca8160c302f13fef4b6aab50a",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultPcrEventLogInvalid, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

//TestImaLogIntegrityImaLogsMissingFault checks the ima log missing in host manifest fault
func TestImaLogIntegrityNoImaLogsFault(t *testing.T) {
	var expectedImaLogs *hvs.Ima

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	result, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestImaLogIntegrityNoPcrValueFault(t *testing.T) {
	expectedImaLogs := &hvs.Ima{
		Measurements: []hvs.Measurements{
			{
				File:        "boot_aggregate",
				Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
			},
			{
				File:        "/root/testFiles1/testfile2.txt",
				Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
			},
			{
				File:        "/root/testFiles1/testfile1.txt",
				Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fd8066de",
			},
		},
	}

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	hostManifest := &hvs.HostManifest{
		HostInfo: model.HostInfo{
			HardwareUUID: "8dbf926c-04d2-03e2-b211-d21d00db521a",
		},
		ImaLogs: &hvs.ImaLogs{
			Pcr: hvs.Pcr{
				Index: 10,
				Bank:  "SHA256",
			},
			ImaTemplate: "ima-ng",
		},
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   0,
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "",
				},
			},
		},
	}

	rule, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
}

func TestImaLogIntegrityUnsupportedSHAAlgorithmFault(t *testing.T) {
	expectedImaLogs := &hvs.Ima{
		Measurements: []hvs.Measurements{
			{
				File:        "boot_aggregate",
				Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
			},
			{
				File:        "/root/testFiles1/testfile2.txt",
				Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
			},
			{
				File:        "/root/testFiles1/testfile1.txt",
				Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fd8066de",
			},
		},
	}

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "",
		},
	}

	hostManifest := &hvs.HostManifest{
		HostInfo: model.HostInfo{
			HardwareUUID: "8dbf926c-04d2-03e2-b211-d21d00db521a",
		},
		ImaLogs: &hvs.ImaLogs{
			Pcr: hvs.Pcr{
				Index: 10,
				Bank:  "SHA256",
			},
			ImaTemplate: "ima-ng",
			Measurements: []hvs.Measurements{
				{
					File:        "boot_aggregate",
					Measurement: "feb805a74e3eb55aa15a492bffaeccbd301432d724f85b96bb88d2dcea9d77a5",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "6b123983d1b7457a2288a7a8edecbafb8fa36c7c03cde81ae9c61795a80467c6",
				},
				{
					File:        "/root/testFiles1/testfile1.txt",
					Measurement: "0f52d8a46fc82a233e4d1bcab2f7a92219b74ba4ff757fb407709817fd8066de",
				},
			},
		},
		PcrManifest: hvs.PcrManifest{
			Sha256Pcrs: []hvs.HostManifestPcrs{
				{
					Index:   10,
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogIntegrity(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	_, err = rule.Apply(hostManifest)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "Error in getting actual Pcr in IMA log Integrity rule: Unsupported sha algorithm ")
}
