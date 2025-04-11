/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"os"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
)

func GetBearerToken() string {
	return strings.TrimSpace(os.Getenv(constants.EnvBearerToken))
}
