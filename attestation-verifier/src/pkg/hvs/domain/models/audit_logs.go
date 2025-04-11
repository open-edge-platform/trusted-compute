/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */

package models

import (
	"time"

	"github.com/google/uuid"
)

type AuditLogEntry struct {
	RowId      int
	ID         uuid.UUID
	EntityID   uuid.UUID
	EntityType string
	CreatedAt  time.Time
	Action     string
	Data       AuditTableData
}

type AuditTableData struct {
	Columns []AuditColumnData
}

type AuditColumnData struct {
	Name      string
	Value     interface{}
	IsUpdated bool
}
