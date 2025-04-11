/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"

	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

// NewPcrEventLogEquals create the rule without the ExcludeTags,Components/labels
// so that all events are evaluated (i.e. no 'excludes').
func NewPcrEventLogEquals(expectedPcrEventLogEntry *hvs.TpmEventLog, flavorID uuid.UUID, marker hvs.FlavorPartName) (Rule, error) {
	var rule pcrEventLogEquals

	rule = pcrEventLogEquals{
		expectedPcrEventLogEntry: expectedPcrEventLogEntry,
		ruleName:                 constants.RulePcrEventLogEquals,
		flavorID:                 &flavorID,
		marker:                   marker,
	}

	return &rule, nil
}

//NewPcrEventLogEqualsExcluding create the rule providing the Exclude tags,Components and labels
//so they are not included for evaluation during 'Apply'.
func NewPcrEventLogEqualsExcluding(expectedPcrEventLogEntry *hvs.TpmEventLog, excludedEvents []string, flavorID uuid.UUID, marker hvs.FlavorPartName) (Rule, error) {
	var rule pcrEventLogEquals

	rule = pcrEventLogEquals{
		expectedPcrEventLogEntry: expectedPcrEventLogEntry,
		excludeTags:              excludedEvents,
		flavorID:                 &flavorID,
		marker:                   marker,
		ruleName:                 constants.RulePcrEventLogEqualsExcluding,
	}

	return &rule, nil
}

type pcrEventLogEquals struct {
	expectedPcrEventLogEntry *hvs.TpmEventLog
	flavorID                 *uuid.UUID
	marker                   hvs.FlavorPartName
	ruleName                 string
	excludeTags              []string
}

// - If the PcrManifest is not present in the host manifest, raise PcrManifestMissing fault.
// - If the PcrManifest's event log is not present in the host manifest, raise PcrEventLogMissing fault.
// - Otherwise, strip out pre-defined events from the host manifest's event log (when 'excludestags' are
//   present) and then subtract 'expected' from 'actual'. If the results are not empty, raise a
//   PcrEventLogContainsUnexpectedEntries fault.
// - Also report the missing events by subtracting 'actual' from 'expected' and raising a
//   PcrEventLogMissingExpectedEntries fault.
func (rule *pcrEventLogEquals) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = rule.ruleName

	result.Rule.ExpectedPcrEventLogEntry = rule.expectedPcrEventLogEntry
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if hostManifest.PcrManifest.IsEmpty() {
		result.Faults = append(result.Faults, newPcrManifestMissingFault())
	} else {

		actualEventLogCriteria, pIndex, bank, err := hostManifest.PcrManifest.PcrEventLogMap.GetEventLogNew(rule.expectedPcrEventLogEntry.Pcr.Bank, rule.expectedPcrEventLogEntry.Pcr.Index)
		if err != nil {
			return nil, errors.Wrap(err, "Error in retrieving the actual event log values in pcr eventlog equals rule")
		}

		if actualEventLogCriteria == nil {
			result.Faults = append(result.Faults, newPcrEventLogMissingFault(hvs.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index), hvs.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)))
		} else {
			actualEventLog := &hvs.TpmEventLog{}
			actualEventLog.TpmEvent = actualEventLogCriteria
			actualEventLog.Pcr.Index = pIndex
			actualEventLog.Pcr.Bank = bank

			// when component excludes are present, strip out the events
			if rule.excludeTags != nil {
				actualEventLog, err = rule.removeExcludedEvents(actualEventLog)
				if err != nil {
					return nil, errors.Wrap(err, "Error in removing the exclude tags from actual event log in pcr eventlog equals rule")
				}
			}

			// now subtract out 'expected'
			unexpectedEventLogs, unexpectedFields, err := actualEventLog.Subtract(rule.expectedPcrEventLogEntry)
			if err != nil {
				return nil, errors.Wrap(err, "Error in subtracting expected event logs from actual in pcr eventlog equals rule")
			}

			// if there are any remaining events, then there were unexpected entries...
			if len(unexpectedEventLogs.TpmEvent) > 0 {
				log.Debug("Unexpected eventlogs in pcreventlog equals rule :", unexpectedEventLogs.TpmEvent)
				result.Faults = append(result.Faults, newPcrEventLogContainsUnexpectedEntries(unexpectedEventLogs))
			}

			if len(unexpectedFields.TpmEvent) > 0 {
				log.Debug("Unexpected eventlog fields in pcreventlog equals rule :", unexpectedFields.TpmEvent)
				pcrIndex := hvs.PcrIndex(actualEventLog.Pcr.Index)
				pcrBank := hvs.SHAAlgorithm(actualEventLog.Pcr.Bank)

				mismatchInfo := hvs.MismatchField{
					Name:              constants.PcrEventLogUnexpectedFields,
					Description:       fmt.Sprintf("Module manifest for PCR %d of %s value contains %d unexpected entries", actualEventLog.Pcr.Index, actualEventLog.Pcr.Bank, len(unexpectedFields.TpmEvent)),
					PcrIndex:          &pcrIndex,
					PcrBank:           &pcrBank,
					UnexpectedEntries: unexpectedFields.TpmEvent,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}

			// now, look the other way -- find events that are in actual but not expected (i.e. missing)
			missingEventLogs, missingFields, err := rule.expectedPcrEventLogEntry.Subtract(actualEventLog)
			if err != nil {
				return nil, errors.Wrap(err, "Error in subtracting actual event logs from expected in pcr eventlog equals rule")
			}

			if len(missingEventLogs.TpmEvent) > 0 {
				log.Debug("Missing eventlogs in pcreventlog equals rule :", missingEventLogs.TpmEvent)
				result.Faults = append(result.Faults, newPcrEventLogMissingExpectedEntries(missingEventLogs))
			}

			if len(missingFields.TpmEvent) > 0 {
				log.Debug("Missing eventlog fields in pcreventlog equals rule :", missingFields.TpmEvent)
				pcrIndex := hvs.PcrIndex(rule.expectedPcrEventLogEntry.Pcr.Index)
				pcrBank := hvs.SHAAlgorithm(rule.expectedPcrEventLogEntry.Pcr.Bank)

				mismatchInfo := hvs.MismatchField{
					Name:           constants.PcrEventLogMissingFields,
					Description:    fmt.Sprintf("Module manifest for PCR %d of %s value missing %d expected entries", rule.expectedPcrEventLogEntry.Pcr.Index, rule.expectedPcrEventLogEntry.Pcr.Bank, len(missingFields.TpmEvent)),
					PcrIndex:       &pcrIndex,
					PcrBank:        &pcrBank,
					MissingEntries: missingFields.TpmEvent,
				}
				result.MismatchField = append(result.MismatchField, mismatchInfo)
			}
		}
	}

	return &result, nil
}

// Creates a new EventLogEntry without events given in excludetags

func (rule *pcrEventLogEquals) removeExcludedEvents(pcrEventLogEntry *hvs.TpmEventLog) (*hvs.TpmEventLog, error) {
	var pcrEventLogs *hvs.TpmEventLog

	var eventsWithoutComponentName []hvs.EventLog

	// Loop through the each eventlog and see if it contains the tag given in excludetags[]
	// and if so, do not add it to the results eventlog.
	for _, eventLog := range pcrEventLogEntry.TpmEvent {

		excludeTagPresent := false

		for _, a := range rule.excludeTags {
			if eventLog.Tags != nil {
				for _, tags := range eventLog.Tags {
					if a == tags {
						excludeTagPresent = true
						break
					}
				}
			}
			if excludeTagPresent {
				break
			}
		}

		if excludeTagPresent {
			log.Debugf("Excluding the evaluation of event tyoe '%s'", eventLog.TypeName)
			continue
		}
		eventsWithoutComponentName = append(eventsWithoutComponentName, eventLog)

	}

	pcrEventLogs = &hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: pcrEventLogEntry.Pcr.Index,
			Bank:  pcrEventLogEntry.Pcr.Bank,
		},
		TpmEvent: eventsWithoutComponentName,
	}
	return pcrEventLogs, nil
}
