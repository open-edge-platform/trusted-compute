/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package fds

import (
	"github.com/google/uuid"
	"time"
)

type Host struct {
	Id       uuid.UUID `json:"host_id,omitempty"`
	HostName string    `json:"host_name"`
	HostInfo *HostInfo `json:"host_info"`
	Status   string    `json:"status"`
	ValidTo  time.Time `json:"valid_to"`
}

type HostInfo struct {
	HardwareUUID     uuid.UUID         `json:"hardware_uuid"`
	HardwareFeatures *HardwareFeatures `json:"hardware_features,omitempty"`
}

type HardwareFeatures struct {
	SGX *SGX `json:"SGX,omitempty"`
	TDX *TDX `json:"TDX,omitempty"`
}

type SGX struct {
	Enabled *bool `json:"enabled,omitempty"`
	Meta    *Meta `json:"meta,omitempty"`
}

type TDX struct {
	Enabled *bool `json:"enabled,omitempty"`
	Meta    *Meta `json:"meta,omitempty"`
}

type Meta struct {
	IntegrityEnabled *bool   `json:"integrity_enabled,omitempty"`
	FlcEnabled       *bool   `json:"flc_enabled,omitempty"`
	EpcOffset        *string `json:"epc_offset,omitempty"`
	EpcSize          *string `json:"epc_size,omitempty"`
	TcbUptoDate      *string `json:"tcb_upto_date,omitempty"`
}
