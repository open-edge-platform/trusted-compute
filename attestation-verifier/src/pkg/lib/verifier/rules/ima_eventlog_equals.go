/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

//
// Rule that compares the 'expected' PCR with the value stored in the host manifest.
//

import (
	"fmt"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

//NewImaEventLogEquals collects the expected PCR values
func NewImaEventLogEquals(pcrLogData *hvs.FlavorPcrs, imaLogData *hvs.Ima, marker hvs.FlavorPartName) (Rule, error) {

	if pcrLogData == nil || imaLogData == nil {
		return nil, errors.New("The expected Pcr or Ima log cannot be nil")
	}

	rule := imaEventLogEquals{
		expectedPcr:     pcrLogData,
		expectedImaLogs: imaLogData,
		marker:          marker,
	}

	return &rule, nil
}

type imaEventLogEquals struct {
	expectedPcr     *hvs.FlavorPcrs
	expectedImaLogs *hvs.Ima
	marker          hvs.FlavorPartName
}

func (rule *imaEventLogEquals) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true // default to true, set to false in fault logic
	result.Rule.Name = constants.RuleImaEventLogEquals
	result.Rule.ExpectedImaLogEntry = rule.expectedImaLogs
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.ImaLogs != nil && rule.expectedImaLogs != nil {
		actualImaLogs := hvs.Ima{}
		actualImaLogs.Measurements = hostManifest.ImaLogs.Measurements
		actualImaLogs.ExpectedValue = hostManifest.ImaLogs.ExpectedValue
		actualImaLogs.ImaTemplate = hostManifest.ImaLogs.ImaTemplate
		pcrIndex := hostManifest.ImaLogs.Pcr.Index
		pcrBank := hostManifest.ImaLogs.Pcr.Bank

		//Subtract flavor data from hostmanifest
		unexpectedImaLogs, mismatchedImaLogs, err := actualImaLogs.Subtract(rule.expectedImaLogs)
		if err != nil {
			return nil, errors.Wrap(err, "Error in subtracting expected IMA logs from actual in hostmanifest IMA logs")
		}

		// if there are any remaining events, then there were unexpected entries...
		if len(unexpectedImaLogs.Measurements) > 0 {
			log.Debug("Unexpected Imalogs in IMA event logs equal rule :", unexpectedImaLogs.Measurements)
			result.Faults = append(result.Faults, newImaLogContainsUnexpectedEntries(unexpectedImaLogs, hostManifest.ImaLogs.Pcr.Index, hostManifest.ImaLogs.Pcr.Bank))
		}

		//Subtract hostmanifest data from flavor
		//leave catching mismatch entries, as they were captured already in above subtract call
		missingImaLogs, _, err := rule.expectedImaLogs.Subtract(&actualImaLogs)
		if err != nil {
			return nil, errors.Wrap(err, "Error in subtracting actual IMA logs from expected IMA logs")
		}

		// if there are any remaining events, then there were missing entries...
		if len(missingImaLogs.Measurements) > 0 {
			log.Debug("Missing Imalogs in IMA event logs equal rule :", missingImaLogs.Measurements)
			result.Faults = append(result.Faults, newImaLogMissingExpectedEntries(missingImaLogs, hostManifest.ImaLogs.Pcr.Index, hostManifest.ImaLogs.Pcr.Bank))
		}

		if len(mismatchedImaLogs.Measurements) > 0 {
			log.Debug("Mismatched Imalogs in IMA event logs equals rule :", mismatchedImaLogs.Measurements)

			for _, expectedMeasurement := range mismatchedImaLogs.Measurements {
				for _, actualMeasurement := range hostManifest.ImaLogs.Measurements {
					if expectedMeasurement.File == actualMeasurement.File {
						result.Faults = append(result.Faults, newImaLogMismatchFault(expectedMeasurement, actualMeasurement, hostManifest.ImaLogs.Pcr.Index, hostManifest.ImaLogs.Pcr.Bank))
					}
				}
			}

			mismatchInfo := hvs.MismatchField{
				Name:                 constants.FaultPcrValueMismatch,
				Description:          fmt.Sprintf("Module manifest for PCR %d of %s value contains %d mismatched entries", pcrIndex, pcrBank, len(mismatchedImaLogs.Measurements)),
				PcrIndex:             (*hvs.PcrIndex)(&pcrIndex),
				PcrBank:              (*hvs.SHAAlgorithm)(&pcrBank),
				MismatchedImaEntries: mismatchedImaLogs.Measurements,
			}
			result.MismatchField = append(result.MismatchField, mismatchInfo)
		}

	} else {
		result.Faults = append(result.Faults, newImaLogsMissingFault())
	}

	return &result, nil
}
