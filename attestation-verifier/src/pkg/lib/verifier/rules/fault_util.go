/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

//
// This file contains utility functions that support a 'rules' ability to add 'faults'
// to a 'hvs.RuleResult'.
//

import (
	"fmt"

	"github.com/google/uuid"
	faultsConst "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func newPcrValueMissingFault(bank hvs.SHAAlgorithm, pcrIndex hvs.PcrIndex) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrValueMissing,
		Description: fmt.Sprintf("Host report does not include required PCR %d, bank %s", pcrIndex, bank),
		PcrIndex:    &pcrIndex,
	}
}

func newPcrValueMismatchFault(pcrIndex hvs.PcrIndex, PcrBank hvs.SHAAlgorithm, expectedPcr hvs.FlavorPcrs, actualPcr hvs.HostManifestPcrs) hvs.Fault {
	return hvs.Fault{
		Name:             faultsConst.FaultPcrValueMismatch + string(actualPcr.PcrBank),
		Description:      fmt.Sprintf("Host PCR %d of %s with value '%s' does not match expected value '%s'", pcrIndex, PcrBank, actualPcr.Value, expectedPcr.Measurement),
		PcrIndex:         &pcrIndex,
		PcrBank:          &PcrBank,
		ExpectedPcrValue: &expectedPcr.Measurement,
		ActualPcrValue:   &actualPcr.Value,
	}
}

func newPcrEventLogMissingExpectedEntries(pcrEventLogEntry *hvs.TpmEventLog) hvs.Fault {
	pIndex := hvs.PcrIndex(pcrEventLogEntry.Pcr.Index)
	pBank := hvs.SHAAlgorithm(pcrEventLogEntry.Pcr.Bank)
	return hvs.Fault{
		Name:           faultsConst.FaultPcrEventLogMissingExpectedEntries,
		Description:    fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", pcrEventLogEntry.Pcr.Index, pcrEventLogEntry.Pcr.Bank, len(pcrEventLogEntry.TpmEvent)),
		PcrIndex:       &pIndex,
		PcrBank:        &pBank,
		MissingEntries: pcrEventLogEntry.TpmEvent,
	}
}

func newPcrEventLogMissingFault(pcrIndex hvs.PcrIndex, PcrBank hvs.SHAAlgorithm) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrEventLogMissing,
		Description: fmt.Sprintf("Host report does not include a PCR Event Log for PCR %d of %s value", pcrIndex, PcrBank),
		PcrIndex:    &pcrIndex,
		PcrBank:     &PcrBank,
	}
}

func newPcrEventLogContainsUnexpectedEntries(pcrEventLogEntry *hvs.TpmEventLog) hvs.Fault {
	pIndex := hvs.PcrIndex(pcrEventLogEntry.Pcr.Index)
	pBank := hvs.SHAAlgorithm(pcrEventLogEntry.Pcr.Bank)
	return hvs.Fault{
		Name:              faultsConst.FaultPcrEventLogContainsUnexpectedEntries,
		Description:       fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", pcrEventLogEntry.Pcr.Index, pcrEventLogEntry.Pcr.Bank, len(pcrEventLogEntry.TpmEvent)),
		PcrIndex:          &pIndex,
		PcrBank:           &pBank,
		UnexpectedEntries: pcrEventLogEntry.TpmEvent,
	}
}

func newXmlEventLogMissingFault(flavorId uuid.UUID) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultXmlMeasurementLogMissing,
		Description: fmt.Sprintf("Host report does not contain XML Measurement log for flavor %s.", flavorId),
	}
}

func newXmlMeasurementValueMismatch(expectedCumulativeHash string, actualCumulativeHash string) hvs.Fault {
	return hvs.Fault{
		Name:          faultsConst.FaultXmlMeasurementValueMismatch,
		Description:   fmt.Sprintf("Host XML measurement log final hash with value '%s' does not match expected value '%s'", actualCumulativeHash, expectedCumulativeHash),
		ExpectedValue: &expectedCumulativeHash,
		ActualValue:   &actualCumulativeHash,
	}
}

func newFlavorSignatureVerificationFailed(flavorId uuid.UUID) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultFlavorSignatureVerificationFailed,
		Description: fmt.Sprintf("Signature verification failed for flavor with id %s", flavorId),
	}
}

func newXmlMeasurementLogInvalidFault() hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultXmlMeasurementLogInvalid,
		Description: "Unable to parse one of the measurements present in HostManifest",
	}
}

func newPcrManifestMissingFault() hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrManifestMissing,
		Description: "Host report does not include a PCR Manifest",
	}
}

func newImaLogsMissingFault() hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrEventLogMissing,
		Description: "Host report does not include a IMA log",
	}
}

func newImaLogContainsUnexpectedEntries(imaLogEntry *hvs.Ima, pcrIndex int, pcrBank string) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrEventLogContainsUnexpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", pcrIndex, pcrBank, len(imaLogEntry.Measurements)),
		UnexpectedImaEntries: &hvs.ImaLog{
			Pcr: hvs.Pcr{
				Index: pcrIndex,
				Bank:  pcrBank,
			},
			ImaMeasurements: imaLogEntry.Measurements,
			ImaTemplate:     imaLogEntry.ImaTemplate,
		},
	}
}

func newImaLogMissingExpectedEntries(imaLogEntry *hvs.Ima, pcrIndex int, pcrBank string) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrEventLogMissingExpectedEntries,
		Description: fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", pcrIndex, pcrBank, len(imaLogEntry.Measurements)),
		MissingImaEntries: &hvs.ImaLog{
			Pcr: hvs.Pcr{
				Index: pcrIndex,
				Bank:  pcrBank,
			},
			ImaMeasurements: imaLogEntry.Measurements,
			ImaTemplate:     imaLogEntry.ImaTemplate,
		},
	}
}

func newImaLogMismatchFault(expectedMeasurement hvs.Measurements, actualMeasurement hvs.Measurements, pcrIndex int, pcrBank string) hvs.Fault {
	return hvs.Fault{
		Name:        faultsConst.FaultPcrValueMismatch,
		Description: fmt.Sprintf("Host IMA log %s with value '%s' does not match expected value %s", expectedMeasurement.File, actualMeasurement.Measurement, expectedMeasurement.Measurement),
		PcrIndex:    (*hvs.PcrIndex)(&pcrIndex),
		PcrBank:     (*hvs.SHAAlgorithm)(&pcrBank),
	}
}
