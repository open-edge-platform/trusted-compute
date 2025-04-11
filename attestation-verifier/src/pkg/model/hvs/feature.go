/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

/**
 *
 * @author mullas
 */

// AES_NI
type AES_NI struct {
	Enabled bool `json:"enabled,omitempty"`
}

type HardwareFeature = model.HardwareFeature

type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		MSR     string `json:"msr"`
	} `json:"meta"`
}

type TPM struct {
	HardwareFeature
	Meta struct {
		TPMVersion string   `json:"tpm_version"`
		PCRBanks   []string `json:"pcr_banks"`
	} `json:"meta"`
}

type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled"`
	} `json:"meta"`
}

// Feature encapsulates the presence of various Platform security features on the Host hardware
type Feature struct {
	AES_NI *AES_NI          `json:"AES_NI,omitempty"`
	TXT    *HardwareFeature `json:"TXT,omitempty"`
	TPM    *TPM             `json:"TPM,omitempty"`
	CBNT   *CBNT            `json:"CBNT,omitempty"`
	UEFI   *UEFI            `json:"UEFI,omitempty"`
	PFR    *HardwareFeature `json:"PFR,omitempty"`
	BMC    *HardwareFeature `json:"BMC,omitempty"`
}
