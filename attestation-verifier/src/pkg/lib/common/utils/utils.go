/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import "os"

func IsContainerEnv() bool {
	if _, err := os.Stat("/.container-env"); err == nil {
		return true
	}
	return false
}
