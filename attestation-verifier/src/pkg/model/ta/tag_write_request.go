/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

// json request format sent from VS...
// {
//     "tag"             : "tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=",
//     "hardware_uuid"   : "7a569dad-2d82-49e4-9156-069b0065b262"
// }
type TagWriteRequest struct {
	Tag          []byte `json:"tag"`
	HardwareUUID string `json:"hardware_uuid"`
}
