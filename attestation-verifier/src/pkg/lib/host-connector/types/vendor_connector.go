/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"

type VendorConnector struct {
	Vendor        constants.Vendor
	Url           string
	Configuration struct {
		Hostname string
		Username string
		Password string
	}
}
