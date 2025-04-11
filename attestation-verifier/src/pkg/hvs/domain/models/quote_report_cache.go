/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

type QuoteReportCache struct {
	QuoteDigest  string
	TrustPcrList []int
	TrustReport  *hvs.TrustReport
}
