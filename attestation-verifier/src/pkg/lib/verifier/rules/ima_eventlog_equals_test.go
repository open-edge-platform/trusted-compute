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

func TestImaEventLogEqualsNoFault(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "a9ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
					},
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
					},
					{
						File:        "/root/testFiles1/testfile1.txt",
						Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
					},
				},
			},
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
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
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
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
	t.Logf("ImaEventLogEquals rule verified")
}

func TestImaEventLogEqualsContainsUnexpectedEntriesFault(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
					},
				},
			},
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
					Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
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
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrEventLogContainsUnexpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestImaEventLogEqualsMissingExpectedEntriesFault(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
					},
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
					},
					{
						File:        "/root/testFiles1/testfile1.txt",
						Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
					},
				},
			},
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
					Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
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

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrEventLogMissingExpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestImaEventLogEqualsMeasurementMismatchFault(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
					},
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
					},
					{
						File:        "/root/testFiles1/testfile1.txt",
						Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
					},
				},
			},
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
					Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
				},
				{
					File:        "/root/testFiles1/testfile1.txt",
					Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc909",
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

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrValueMismatch)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestImaEventLogEqualsNoImaLogsFault(t *testing.T) {
	var expectedImaLogs *hvs.Ima

	expectedPcr := &hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 10,
			Bank:  "SHA256",
		},
	}

	result, err := NewImaEventLogEquals(expectedPcr, expectedImaLogs, hvs.FlavorPartIma)
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestImaEventLogEqualsContainsUnexpectedEntriesFaultForRepeatedButDifferentFileMeasurementInHostmanifest(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
					},
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
					},
					{
						File:        "/root/testFiles1/testfile1.txt",
						Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
					},
				},
			},
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
					Measurement: "a8ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
				},
				{
					File:        "/root/testFiles1/testfile1.txt",
					Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
				},
				{
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c8888",
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

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrEventLogContainsUnexpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestImaEventLogEqualsMeasurementMissingExpectedEntriesFaultForRepeatedButDifferentFileMeasurementInFlavor(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
					},
					{
						File:        "/root/testFiles1/testfile1.txt",
						Measurement: "d66f10063e36554432b6694f245068dd7d573fddb15d22ed51c4c5c6686fc4b9",
					},
					{
						File:        "/root/testFiles1/testfile2.txt",
						Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c8888",
					},
				},
			},
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
					File:        "/root/testFiles1/testfile2.txt",
					Measurement: "65685ed4d41fdeeac6658eb7b6bc524d5c61e2e86fb96e512be32ec6ec1c0e36",
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
					Value:   "c29a8dd3b4c545129431d25bb0a3d22929101c6630028b06684a20aff944e02f",
					PcrBank: "SHA256",
				},
			},
		},
	}

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, constants.FaultPcrEventLogMissingExpectedEntries)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestImaEventLogEqualsTrueForRepeatedButDifferentFileMeasurementInHostmanifestAndFlavor(t *testing.T) {
	flavorPcr := hvs.SignedFlavor{
		Flavor: hvs.Flavor{
			Pcrs: []hvs.FlavorPcrs{
				{
					Pcr: hvs.Pcr{
						Index: 10,
						Bank:  "SHA256",
					},
				},
			},
			ImaLogs: &hvs.Ima{
				Measurements: []hvs.Measurements{
					{
						File:        "boot_aggregate",
						Measurement: "c3ff266ecedfa2b4683855f4f231761779caddc89ef59996935c4cf8848a88ad",
					},
					{
						File:        "/root/custom-policy/posttest/v1.txt",
						Measurement: "8030404398e6639ff1395dd8e38c782bf6c9e00229adfc54408c967a2e981b51",
					},
					{
						File:        "/root/custom-policy/posttest/v2.txt",
						Measurement: "eb9c26baee47f19e4993a77bca936d0ff09e355a82d3db79bf154ebff1a80604",
					},
					{
						File:        "/root/custom-policy/posttest/v2.txt",
						Measurement: "b8803178047214b86247b6a9e826f356de5e87d55af564f7d971eeec86b38e2e",
					},
				},
			},
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
					Measurement: "c3ff266ecedfa2b4683855f4f231761779caddc89ef59996935c4cf8848a88ad",
				},
				{
					File:        "/root/custom-policy/posttest/v1.txt",
					Measurement: "8030404398e6639ff1395dd8e38c782bf6c9e00229adfc54408c967a2e981b51",
				},
				{
					File:        "/root/custom-policy/posttest/v2.txt",
					Measurement: "eb9c26baee47f19e4993a77bca936d0ff09e355a82d3db79bf154ebff1a80604",
				},
				{
					File:        "/root/custom-policy/posttest/v2.txt",
					Measurement: "b8803178047214b86247b6a9e826f356de5e87d55af564f7d971eeec86b38e2e",
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

	rule, err := NewImaEventLogEquals(&flavorPcr.Flavor.Pcrs[0], flavorPcr.Flavor.ImaLogs, hvs.FlavorPartIma)
	assert.NoError(t, err)

	result, err := rule.Apply(hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
	assert.True(t, result.Trusted)
	t.Logf("ImaEventLogEquals rule verified")
}
