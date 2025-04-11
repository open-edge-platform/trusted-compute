/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package wls

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/pkg/instance"
	"github.com/pkg/errors"
)

type ResultRule struct {
	EncryptionMatches
}

// EncryptionMatches is a rule that enforces image encryption policy
type EncryptionMatches struct {
	RuleName string             `json:"rule_name"`
	Markers  []string           `json:"markers"`
	Expected ExpectedEncryption `json:"expected"`
}

// ExpectedEncryption is a data template that defines the json tag name of the encryption requirement, and the expected boolean value
type ExpectedEncryption struct {
	Name  string `json:"name"`
	Value bool   `json:"value"`
}

// Fault defines failure events when applying a Rule
type Fault struct {
	Description string `json:"description"`
	Cause       error  `json:"cause"`
}

type Result struct {
	Rule     ResultRule `json:"rule"`
	FlavorID string     `json:"flavor_id"`
	Faults   []Fault    `json:"faults,omitempty"`
	Trusted  bool       `json:"trusted"`
}

type InstanceTrustReport struct {
	Manifest   instance.Manifest `json:"instance_manifest"`
	PolicyName string            `json:"policy_name"`
	Results    []Result          `json:"results"`
	Trusted    bool              `json:"trusted"`
}

type Report struct {
	ID string `json:"id,omitempty"`
	InstanceTrustReport
	crypt.SignedData
}

type ReportsResponse []Report

type ReportCollection struct {
	Report []Report `json:"reports"`
}

// Name returns the name of the EncryptionMatches Rule.
func (em *EncryptionMatches) Name() string {
	return em.RuleName
}

// apply returns a true if the rule application concludes the manifest is trusted
// if it returns false, a list of Fault's are supplied explaining why.
func (em *EncryptionMatches) Apply(manifest interface{}) (bool, []Fault) {
	// assert manifest as VmManifest
	if manifest, ok := manifest.(*instance.Manifest); ok {
		// if rule expects encryption_required to be true
		if em.Expected.Value == true {
			// then vmManifest image must be encrypted
			if manifest.ImageEncrypted {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"true\" but Manifest.ImageEncrypted is \"false\"", nil}}
		} else {
			if manifest.ImageEncrypted == false {
				return true, nil
			}
			return false, []Fault{Fault{"encryption_required is \"false\" but Manifest.ImageEncrypted is \"true\"", nil}}
		}
	}
	return false, []Fault{Fault{"invalid manifest type for rule", errors.New("failed to type assert manifest to *instance.Manifest")}}
}
