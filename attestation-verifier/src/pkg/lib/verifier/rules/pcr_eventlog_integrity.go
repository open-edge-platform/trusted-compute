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
func NewPcrEventLogIntegrity(expectedPcr *hvs.FlavorPcrs, marker hvs.FlavorPartName) (Rule, error) {
	var rule pcrEventLogIntegrity

	if expectedPcr == nil {
		return nil, errors.New("The expected pcr cannot be nil")
	}

	rule = pcrEventLogIntegrity{
		expectedPcr: *expectedPcr,
		marker:      marker,
	}

	return &rule, nil
}

type pcrEventLogIntegrity struct {
	expectedPcr hvs.FlavorPcrs
	marker      hvs.FlavorPartName
}

// - If the hostmanifest's PcrManifest is not present, create PcrManifestMissing fault.
// - If the hostmanifest does not contain a pcr at 'expected' bank/index, create a PcrValueMissing fault.
// - If the hostmanifest does not have an event log at 'expected' bank/index, create a
//   PcrEventLogMissing fault.
// - Otherwise, replay the hostmanifest's event log at 'expected' bank/index and verify the
//   the calculated hash matches the pcr value in the host-manifest.  If not, create a PcrEventLogInvalid fault.
func (rule *pcrEventLogIntegrity) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RulePcrEventLogIntegrity

	result.Rule.ExpectedPcr = &rule.expectedPcr
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {
		actualPcr, err := hostManifest.PcrManifest.GetPcrValue(hvs.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), hvs.PcrIndex(rule.expectedPcr.Pcr.Index))
		if err != nil {
			return nil, errors.Wrap(err, "Error in getting actual Pcr in Pcr Eventlog Integrity rule")
		}

		if actualPcr == nil {
			result.Faults = append(result.Faults, newPcrValueMissingFault(hvs.SHAAlgorithm(rule.expectedPcr.Pcr.Bank), hvs.PcrIndex(rule.expectedPcr.Pcr.Index)))
		} else {
			actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLogNew(rule.expectedPcr.Pcr.Bank, rule.expectedPcr.Pcr.Index)
			if err != nil {
				return nil, errors.Wrap(err, "Error in getting actual eventlogs in Pcr Eventlog Integrity rule")
			}

			if actualEventLogCriteria == nil {
				result.Faults = append(result.Faults, newPcrEventLogMissingFault(hvs.PcrIndex(rule.expectedPcr.Pcr.Index), hvs.SHAAlgorithm(rule.expectedPcr.Pcr.Bank)))
			} else {
				actualEventLog := &hvs.TpmEventLog{}
				actualEventLog.TpmEvent = actualEventLogCriteria
				actualEventLog.Pcr.Index = pIndex
				actualEventLog.Pcr.Bank = bank

				calculatedValue, err := actualEventLog.Replay()
				if err != nil {
					return nil, errors.Wrap(err, "Error in calculating replay in Pcr Eventlog Integrity rule")
				}

				if calculatedValue != actualPcr.Value {
					PI := hvs.PcrIndex(rule.expectedPcr.Pcr.Index)
					fault := hvs.Fault{
						Name:            constants.FaultPcrEventLogInvalid,
						Description:     fmt.Sprintf("PCR %d Event Log is invalid,mismatches between calculated event log values %s and actual pcr values %s", rule.expectedPcr.Pcr.Index, calculatedValue, actualPcr.Value),
						PcrIndex:        &PI,
						CalculatedValue: &calculatedValue,
						ActualPcrValue:  &actualPcr.Value,
					}
					result.Faults = append(result.Faults, fault)
				}
			}
		}
	}

	return &result, nil
}
