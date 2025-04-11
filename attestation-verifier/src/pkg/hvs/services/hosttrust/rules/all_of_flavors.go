/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package rules

import (
	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	flavorVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

type AllOfFlavors struct {
	AllOfFlavors                    []hvs.SignedFlavor
	Result                          *hvs.RuleResult
	Markers                         []hvs.FlavorPartName
	SkipFlavorSignatureVerification bool
	verifierCerts                   flavorVerifier.VerifierCertificates
}

func NewAllOfFlavors(flavors []hvs.SignedFlavor, markers []hvs.FlavorPartName, skipFlavorSignatureVerification bool, verifierCerts flavorVerifier.VerifierCertificates) AllOfFlavors {
	return AllOfFlavors{
		AllOfFlavors:                    flavors,
		Markers:                         markers,
		SkipFlavorSignatureVerification: skipFlavorSignatureVerification,
		verifierCerts:                   verifierCerts,
	}
}

var defaultLog = commLog.GetDefaultLogger()

func (aof *AllOfFlavors) AddFaults(report *hvs.TrustReport) (*hvs.TrustReport, error) {

	if report == nil {
		return nil, nil
	}
	faultsExist := false
	hostManifest := &report.HostManifest
	aofMissingFlavorParts := make(map[string]bool)
	for _, flavor := range aof.AllOfFlavors {
		ruleFactory := flavorVerifier.NewRuleFactory(aof.verifierCerts, hostManifest, &flavor, aof.SkipFlavorSignatureVerification)
		policyRules, _, err := ruleFactory.GetVerificationRules()
		if err != nil {
			return nil, err
		}
		for _, policyRule := range policyRules {
			result, err := policyRule.Apply(hostManifest)
			if err != nil {
				return report, errors.Wrap(err, "Failed to apply rule \""+report.PolicyName+"\" to host manifest of "+report.HostManifest.HostInfo.HostName)
			}

			if result != nil {
				result.FlavorId = &flavor.Flavor.Meta.ID
				result.Trusted = result.IsTrusted()
				report.AddResult(*result)
				if !result.Trusted {
					faultsExist = true
					aofMissingFlavorParts[flavor.Flavor.Meta.Description[hvs.FlavorPartDescription].(string)] = true
					defaultLog.Infof("All of Flavor types missing for flavor id: %s and flavor part: %s",
						result.FlavorId, flavor.Flavor.Meta.Description[hvs.FlavorPartDescription].(string))
				}
			}

		}
	}
	if faultsExist {
		for flvrPart := range aofMissingFlavorParts {
			ruleResult := hvs.RuleResult{
				//FlavorVerify.java 585
				Rule:     hvs.RuleInfo{Markers: aof.Markers},
				FlavorId: nil,
				Faults: []hvs.Fault{
					{
						Name:        constants.FaultAllofFlavorsMissing,
						Description: "All of Flavor Types Missing : " + flvrPart,
					},
				},
			}
			report.AddResult(ruleResult)
		}
	}
	return report, nil
}

// RuleAllOfFlavors.java: 81
// checkAllOfFlavorsExist(TrustReport trustReport)
// this function does the same apply operations as addFaults
// and the flow in code seems to utilize it before calling addFaults
// for optimizing reason...probably better get rid of it
func (aof *AllOfFlavors) CheckAllOfFlavorsExist(report *hvs.TrustReport) bool {
	if report == nil ||
		aof.AllOfFlavors == nil {
		return false
	}
	hostManifest := &report.HostManifest
	for _, flavor := range aof.AllOfFlavors {
		ruleFactory := flavorVerifier.NewRuleFactory(aof.verifierCerts, hostManifest, &flavor, aof.SkipFlavorSignatureVerification)
		policyRules, _, err := ruleFactory.GetVerificationRules()
		if err != nil {
			defaultLog.WithError(err).Debug("hosttrust/all_of_flavors:checkAllOfFlavorsExist() Error applying vendor trust policy rule")
			return false
		}
		for _, policyRule := range policyRules {
			result, err := policyRule.Apply(hostManifest)
			if err != nil {
				defaultLog.WithError(err).Debug("hosttrust/all_of_flavors:checkAllOfFlavorsExist() Error applying vendor trust policy rule")
				return false
			}
			if result != nil && !result.IsTrusted() {
				return false
			}
		}
	}
	return true
}
