/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// NewPcrEventLogIntegrity creates a rule that will check if a PCR (in the host-manifest only)
// has a "calculated hash" (i.e. from event log replay) that matches its actual hash.
func NewImaEventLogIntegrity(pcrData *hvs.FlavorPcrs, expectedImaMeasurements *hvs.Ima, marker hvs.FlavorPartName) (Rule, error) {
	var rule imaLogIntegrity

	if expectedImaMeasurements == nil || pcrData == nil {
		return nil, errors.New("The expected pcr or Ima log cannot be nil")
	}

	rule = imaLogIntegrity{
		expectedPcr:     pcrData,
		expectedImaLogs: expectedImaMeasurements,
		marker:          marker,
	}

	return &rule, nil
}

type imaLogIntegrity struct {
	expectedPcr     *hvs.FlavorPcrs
	expectedImaLogs *hvs.Ima
	marker          hvs.FlavorPartName
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the
//   the calculated hash matches the pcr value in the host-manifest.  If not, create a PcrEventLogInvalid fault.
func (rule *imaLogIntegrity) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}

	result.Trusted = true
	result.Rule.Name = constants.RuleImaMeasurementLogIntegrity
	result.Rule.ExpectedPcr = rule.expectedPcr
	result.Rule.ExpectedImaLogEntry = rule.expectedImaLogs
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	//Check if hostmanifest has imalog
	if hostManifest.ImaLogs != nil && rule.expectedImaLogs != nil {
		if len(hostManifest.ImaLogs.Measurements) == 0 && len(rule.expectedImaLogs.Measurements) == 0 {
			result.Faults = append(result.Faults, newImaLogsMissingFault())
		} else {
			actualPcr, err := hostManifest.PcrManifest.GetPcrValue(hvs.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), hvs.PcrIndex(rule.expectedPcr.Pcr.Index))
			if err != nil {
				return nil, errors.Wrap(err, "Error in getting actual Pcr in IMA log Integrity rule")
			}

			if actualPcr == nil {
				result.Faults = append(result.Faults, newPcrValueMissingFault(hvs.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), hvs.PcrIndex(rule.expectedPcr.Pcr.Index)))
			} else {
				actualImaLog := &hvs.ImaLogs{}
				actualImaLog.Measurements = hostManifest.ImaLogs.Measurements
				actualImaLog.Pcr.Index = hostManifest.ImaLogs.Pcr.Index
				actualImaLog.Pcr.Bank = hostManifest.ImaLogs.Pcr.Bank
				actualImaLog.ImaTemplate = hostManifest.ImaLogs.ImaTemplate

				calculatedValue, err := actualImaLog.Replay()
				if err != nil {
					return nil, errors.Wrap(err, "Error in calculating replay in IMA log Integrity rule")
				}

				if calculatedValue != actualPcr.Value {
					PI := hvs.PcrIndex(rule.expectedPcr.Pcr.Index)
					fault := hvs.Fault{
						Name:            constants.FaultPcrEventLogInvalid,
						Description:     fmt.Sprintf("PCR %d IMA Log is invalid,mismatches between calculated IMA log values %s and actual pcr values %s", rule.expectedPcr.Pcr.Index, calculatedValue, actualPcr.Value),
						PcrIndex:        &PI,
						CalculatedValue: &calculatedValue,
						ActualPcrValue:  &actualPcr.Value,
					}
					result.Faults = append(result.Faults, fault)
				}
			}
		}
	} else {
		result.Faults = append(result.Faults, newImaLogsMissingFault())
	}
	return &result, nil
}
