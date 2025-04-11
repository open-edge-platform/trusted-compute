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

//NewPcrEventLogIncludes creates the rule that will check
//if all the actual event log measurements included in expected
func NewPcrEventLogIncludes(expectedPcrEventLogEntry *hvs.TpmEventLog, marker hvs.FlavorPartName) (Rule, error) {
	var rule pcrEventLogIncludes

	if expectedPcrEventLogEntry == nil {
		return nil, errors.New("The expected event log cannot be nil")
	}

	if expectedPcrEventLogEntry != nil {
		rule = pcrEventLogIncludes{
			expectedPcrEventLogEntry: expectedPcrEventLogEntry,
			marker:                   marker,
		}
	}

	return &rule, nil
}

type pcrEventLogIncludes struct {
	expectedPcrEventLogEntry *hvs.TpmEventLog
	marker                   hvs.FlavorPartName
}

// - If the PcrManifest is not present in the host manifest, raise PcrManifestMissing fault.
// - if the host manifest does not have any log entries, or it doesn't have any value
//   at the bank/index 'expected', raise "PcrEventLogMissing".
// - if the log at bank/index does not have the same events as 'expected', raise
//   "PcrEventLogMissingExpectedEntries".
func (rule *pcrEventLogIncludes) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RulePcrEventLogIncludes

	result.Rule.Markers = append(result.Rule.Markers, rule.marker)
	result.Rule.ExpectedPcrEventLogEntry = rule.expectedPcrEventLogEntry

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {

		actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLogNew(rule.expectedPcrEventLogEntry.Pcr.Bank, rule.expectedPcrEventLogEntry.Pcr.Index)
		if err != nil {
			return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr event log includes rule")
		}

		if actualEventLogCriteria == nil {
			result.Faults = append(result.Faults, newPcrEventLogMissingFault(hvs.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index), hvs.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)))
		} else {
			actualEventLog := &hvs.TpmEventLog{}
			actualEventLog.TpmEvent = actualEventLogCriteria
			actualEventLog.Pcr.Index = pIndex
			actualEventLog.Pcr.Bank = bank

			// subtract the 'actual' event log measurements from 'expected'.
			// if there are any left in 'expected', then 'actual' did not include all entries
			missingEvents, missingAttr, err := rule.expectedPcrEventLogEntry.Subtract(actualEventLog)
			if err != nil {
				return nil, errors.Wrap(err, "Error subtracting actual from expected event logs in pcr eventlog includes rule.")
			}

			if len(missingEvents.TpmEvent) > 0 {
				log.Debug("Missing eventlogs in pcreventlog includes rule :", missingEvents.TpmEvent)
				result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEvents))
			}

			if len(missingAttr.TpmEvent) > 0 {
				log.Debug("Missing eventlog fields in pcrevent includes equals rule :", missingAttr.TpmEvent)
				index := hvs.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index)
				bank := hvs.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)

				mismatchInfo := hvs.MismatchField{
					Name:           constants.PcrEventLogMissingFields,
					Description:    fmt.Sprintf("Module manifest for PCR %d of %s value contains %d missing entries", rule.expectedPcrEventLogEntry.Pcr.Index, rule.expectedPcrEventLogEntry.Pcr.Bank, len(missingAttr.TpmEvent)),
					PcrIndex:       &index,
					PcrBank:        &bank,
					MissingEntries: missingAttr.TpmEvent,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}
		}
	}

	return &result, nil
}
