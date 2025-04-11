/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

type Permission struct {
	ID        string     `json:"permission_id,omitempty" gorm:"primary_key;type:uuid"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-"`

	Rule string `json:"rule"`
}

type PermissionSearch struct {
	Rule         string `json:"rule"`
	RuleContains string
	IDFilter     []string
}

type Permissions []Permission
