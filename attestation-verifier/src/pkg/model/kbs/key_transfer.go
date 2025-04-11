/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package kbs

type KeyTransferResponse struct {
	WrappedKey string `json:"wrapped_key"`
	WrappedSWK string `json:"wrapped_swk,omitempty"`
}

type SKCKeyTransferResponse struct {
	KeyInfo   KeyTransferAttributes `json:"data"`
	Operation string                `json:"operation"`
	Status    string                `json:"status"`
}
