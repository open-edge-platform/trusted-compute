/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"github.com/google/uuid"
	"time"
)

type HostCredential struct {
	Id           uuid.UUID `json:"id"`
	HostId       uuid.UUID `json:"host_id,omitempty"`
	HostName     string    `json:"host_name,omitempty"`
	HardwareUuid HwUUID    `json:"hardware_uuid,omitempty"`
	Credential   string    `json:"credential"`
	CreatedTs    time.Time `json:"created_ts,omitempty"`
}
