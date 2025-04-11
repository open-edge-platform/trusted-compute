/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aps

type AttestationType string

const (
	TDX AttestationType = "TDX"
	SGX AttestationType = "SGX"
)

func (at AttestationType) String() string {
	return string(at)
}

func (at AttestationType) Valid() bool {
	switch at {
	case TDX, SGX:
		return true
	}
	return false
}
