/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package verifier

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier/rules"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

type vendorTrustPolicyReader interface {
	Rules() []rules.Rule
}

type hostTrustPolicyManager struct {
}

func NewHostTrustPolicyManager(hvs.Flavor, *hvs.HostManifest) *hostTrustPolicyManager {
	return &hostTrustPolicyManager{}
}

func (htpm *hostTrustPolicyManager) GetVendorTrustPolicyReader() vendorTrustPolicyReader {
	return nil
}
