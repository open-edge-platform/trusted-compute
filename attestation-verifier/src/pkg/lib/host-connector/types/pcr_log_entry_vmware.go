/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package types

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

type EventDetails struct {
	DataHash           []int
	DataHashMethod     hvs.SHAAlgorithm
	ComponentName      *string
	VibName            *string
	VibVersion         *string
	VibVendor          *string
	CommandLine        *string
	OptionsFileName    *string
	BootOptions        *string
	BootSecurityOption *string
}

type TpmEvent struct {
	PcrIndex     int
	EventDetails EventDetails
}
