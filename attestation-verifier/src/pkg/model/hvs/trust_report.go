/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

//
// TrustReport model returned by verifier.Verify()
//

import (
	"github.com/google/uuid"
	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	ta "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

type TrustReport struct {
	PolicyName   string       `json:"policy_name"`
	Results      []RuleResult `json:"results"`
	Trusted      bool         `json:"trusted"`
	HostManifest HostManifest `json:"host_manifest"`
}

type RuleResult struct {
	Rule           RuleInfo        `json:"rule"`
	FlavorId       *uuid.UUID      `json:"flavor_id,omitempty"`
	MismatchField  []MismatchField `json:"mismatch_fields,omitempty"`
	Faults         []Fault         `json:"faults,omitempty"`
	Trusted        bool            `json:"trusted"`
	AdditionalInfo *AdditionalInfo `json:"additional_info,omitempty"`
}

type AdditionalInfo struct {
	FileList    []string `json:"file_list,omitempty"`
	Description string   `json:"description,omitempty"`
}

type MismatchField struct {
	Name                 string         `json:"name"`
	Description          string         `json:"description"`
	PcrIndex             *PcrIndex      `json:"pcr_index,omitempty"`
	PcrBank              *SHAAlgorithm  `json:"pcr_bank,omitempty"`
	MissingEntries       []EventLog     `json:"missing_entries,omitempty"`
	UnexpectedEntries    []EventLog     `json:"unexpected_entries,omitempty"`
	UnexpectedImaEntries []Measurements `json:"unexpected_ima_entries,omitempty"`
	MismatchedImaEntries []Measurements `json:"mismatched_ima_entries,omitempty"`
}

type RuleInfo struct {
	Name                     string                 `json:"rule_name,omitempty"`
	Markers                  []FlavorPartName       `json:"markers,omitempty"`
	ExpectedPcr              *FlavorPcrs            `json:"expected_pcr,omitempty"`
	PCR                      *Pcr                   `json:"pcr,omitempty"`
	Measurement              string                 `json:"measurement,omitempty"` //required
	PCRMatches               bool                   `json:"pcr_matches,omitempty"`
	FlavorID                 *uuid.UUID             `json:"flavor_id,omitempty"`
	FlavorName               *string                `json:"flavor_name,omitempty"`
	ExpectedValue            *string                `json:"expected_value,omitempty"`
	ExpectedMeasurements     []ta.FlavorMeasurement `json:"expected_measurements,omitempty"`
	ExpectedPcrEventLogEntry *TpmEventLog           `json:"expected_pcrvalues,omitempty"`
	Exclude_Tags             []string               `json:"excluding_tag,omitempty"`
	ExpectedTag              []byte                 `json:"expected_tag,omitempty"`
	Tags                     map[string]string      `json:"tags,omitempty"`
	ExpectedImaLogEntry      *Ima                   `json:"expected_imavalues,omitempty"`
}

type Fault struct {
	Name                   string                 `json:"fault_name"`
	Description            string                 `json:"description"`
	PcrIndex               *PcrIndex              `json:"pcr_index,omitempty"`
	PcrBank                *SHAAlgorithm          `json:"pcr_bank,omitempty"`
	ExpectedPcrValue       *string                `json:"expected_pcrvalue,omitempty"`
	ActualPcrValue         *string                `json:"actual_pcrvalue,omitempty"`
	MissingEntries         []EventLog             `json:"missing_entries,omitempty"`
	UnexpectedEntries      []EventLog             `json:"unexpected_entries,omitempty"`
	UnexpectedImaEntries   *ImaLog                `json:"unexpected_ima_entries,omitempty"`
	MissingImaEntries      *ImaLog                `json:"missing_ima_entries,omitempty"`
	ExcludeTags            []string               `json:"exclude_tags,omitempty"`
	FlavorId               *uuid.UUID             `json:"flavor_id,omitempty"`
	UnexpectedMeasurements []ta.FlavorMeasurement `json:"unexpected_measurements,omitempty"`
	MissingMeasurements    []ta.FlavorMeasurement `json:"missing_measurements,omitempty"`
	MismatchMeasurements   []ta.FlavorMeasurement `json:"mismatch_measurements,omitempty"`
	ExpectedValue          *string                `json:"expected_value,omitempty"`
	CalculatedValue        *string                `json:"calculated_value,omitempty"`
	ActualValue            *string                `json:"actual_value,omitempty"`
	MeasurementId          *string                `json:"measurement_id,omitempty"`
	FlavorDigestAlg        *string                `json:"flavor_digest_alg,omitempty"`
	MeasurementDigestAlg   *string                `json:"measurement_digest_alg,omitempty"`
	FileName               string                 `json:"file_name,omitempty"`
}

func NewTrustReport(report TrustReport) *TrustReport {
	return &TrustReport{PolicyName: report.PolicyName, Results: report.Results, Trusted: report.Trusted}
}

func (t *TrustReport) IsTrusted() bool {
	return t.isTrustedForResults(t.Results)
}

func (t *TrustReport) IsTrustedForMarker(marker string) bool {
	return t.isTrustedForResults(t.GetResultsForMarker(marker))
}
func (t *TrustReport) isTrustedForResults(ruleResults []RuleResult) bool {
	if len(ruleResults) == 0 {
		return false // empty policy is not trusted;  like RequireAllEmptySet fault.
	}

	trusted := true

	for _, result := range ruleResults {
		trusted = trusted && result.IsTrusted()
	}

	return trusted
}

func (t *TrustReport) GetResultsForMarker(marker string) []RuleResult {
	var ruleResults []RuleResult
	for _, result := range t.Results {
		markers := result.Rule.Markers
		if markers != nil {
			if find(markers, marker) {
				ruleResults = append(ruleResults, result)
			}
		}
	}
	return ruleResults
}

// TrustReport.java 106
func (t *TrustReport) CheckResultExists(targetRuleResult RuleResult) bool {
	//In TrustReport.java 107 marker := targetRuleResult.Rule.Markers[0] why dont we iterate all over the markers?
	marker := targetRuleResult.Rule.Markers[0]
	combinedRuleResults := t.GetResultsForMarker(marker.String())
	for _, ruleResult := range combinedRuleResults {
		if targetRuleResult.equals(ruleResult) {
			switch ruleResult.Rule.Name {
			case constants.RulePcrEventLogEqualsExcluding,
				constants.RulePcrEventLogIncludes,
				constants.RulePcrEventLogIntegrity,
				constants.RulePcrEventLogEquals,
				constants.RulePcrMatchesConstant:
				// Compare pcrs for only these rules, all other rules will have pcr expected entry = nil
				// We need to take care same rule does not get repeated in report, hence exclude value for PCR match
				// as in case of rules like RulePcrEventLogIncludes, RulePcrEventLogEqualsExcluding etc actual PCR value can be different
				if targetRuleResult.Rule.ExpectedPcr == nil {
					return false
				} else if targetRuleResult.Rule.ExpectedPcr.EqualsWithoutValue(*ruleResult.Rule.ExpectedPcr) {
					return true
				} else {
					continue
				}
			default:
				if len(targetRuleResult.Faults) > 0 {
					return false
				}
				return true
			}
		}
	}
	return false
}

func (t *TrustReport) AddResults(ruleResults []RuleResult) {
	for _, ruleResult := range ruleResults {
		t.AddResult(ruleResult)
	}
}

func (t *TrustReport) AddResult(ruleResult RuleResult) {
	if !t.CheckResultExists(ruleResult) {
		t.Results = append(t.Results, ruleResult)
	}
}

func find(slice []FlavorPartName, val string) bool {
	for _, item := range slice {
		if item.String() == val {
			return true
		}
	}
	return false
}

func (r *RuleResult) equals(target RuleResult) bool {
	if target.Rule.Name == r.Rule.Name {
		return true
	}
	return false
}

func (r *RuleResult) IsTrusted() bool {
	if r.Faults == nil || len(r.Faults) == 0 {
		return true
	}
	return false
}
