/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package rules

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

//TODO move to verifier
type RequiredFlavorTypeExists struct {
	FlavorPart hvs.FlavorPartName
}

func NewRequiredFlavorTypeExists(flavorPart hvs.FlavorPartName) *RequiredFlavorTypeExists {
	return &RequiredFlavorTypeExists{
		FlavorPart: flavorPart,
	}
}

func (r *RequiredFlavorTypeExists) Apply(trustReport hvs.TrustReport) *hvs.TrustReport {

	var markers []hvs.FlavorPartName
	//RequiredFlavorTypeExists.java 36
	if r.isFlavorPartMissing(trustReport) {
		ruleResult := hvs.RuleResult{
			Rule: hvs.RuleInfo{
				Markers: append(markers, r.FlavorPart),
			},
		}

		fault := hvs.Fault{
			Name:        constants.FaultRequiredFlavorTypeMissing,
			Description: fmt.Sprintf("Required flavor type missing: %s", r.FlavorPart.String()),
		}
		defaultLog.Debugf("Defined and required flavor part [%s] is missing", r.FlavorPart.String())
		ruleResult.Faults = append(ruleResult.Faults, fault)
		trustReport.AddResult(ruleResult)
	}

	return &trustReport
}

func (r *RequiredFlavorTypeExists) isFlavorPartMissing(trustReport hvs.TrustReport) bool {
	if trustReport.GetResultsForMarker(r.FlavorPart.String()) != nil && len(trustReport.GetResultsForMarker(r.FlavorPart.String())) != 0 {
		return false
	}
	return true
}
