/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Builds rules for "vmware" vendor and TPM 1.2
//

import (
	hvsconstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier/rules"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

type ruleBuilderVMWare12 struct {
	verifierCertificates VerifierCertificates
	hostManifest         *hvs.HostManifest
	signedFlavor         *hvs.SignedFlavor
	rules                []rules.Rule
}

func newRuleBuilderVMWare12(verifierCertificates VerifierCertificates, hostManifest *hvs.HostManifest, signedFlavor *hvs.SignedFlavor) (ruleBuilder, error) {
	builder := ruleBuilderVMWare12{
		verifierCertificates: verifierCertificates,
		hostManifest:         hostManifest,
		signedFlavor:         signedFlavor,
	}

	return &builder, nil
}

func (builder *ruleBuilderVMWare12) GetName() string {
	return hvsconstants.VmwareBuilder
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// TagCertificateTrusted
// PcrMatchesConstant rule for PCR 22
func (builder *ruleBuilderVMWare12) GetAssetTagRules() ([]rules.Rule, error) {

	var results []rules.Rule
	//
	// TagCertificateTrusted
	//
	tagCertificateTrusted, err := getTagCertificateTrustedRule(builder.verifierCertificates.AssetTagCACertificates, &builder.signedFlavor.Flavor)
	if err != nil {
		return nil, err
	}
	results = append(results, tagCertificateTrusted)

	return results, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare12) GetAikCertificateTrustedRule(fp hvs.FlavorPartName) ([]rules.Rule, error) {
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare12) GetSoftwareRules() ([]rules.Rule, error) {
	return nil, nil
}

// From 'design' repo at isecl/libraries/verifier/verifier.md...
// (none)
func (builder *ruleBuilderVMWare12) GetImaRules(rule *hvs.FlavorPcrs, flavor hvs.Flavor, flavorPartName hvs.FlavorPartName) ([]rules.Rule, error) {
	return nil, nil
}
