/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package wls

//FlavorKey is a representation of flavor-key information
type FlavorKey struct {
	Flavor    Image  `json:"flavor"`
	Signature string `json:"signature"`
	Key       []byte `json:"key,omitempty"`
}

// ReturnKey to return key Json
type ReturnKey struct {
	Key []byte `json:"key"`
}

// RequestKey struct defines input parameters to retrieve a key
type RequestKey struct {
	HwId   string `json:"hardware_uuid"`
	KeyUrl string `json:"key_url"`
}
