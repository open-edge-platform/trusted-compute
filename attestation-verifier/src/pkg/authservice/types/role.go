/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	. "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"time"
)

type Role struct {
	ID        string     `json:"role_id,omitempty" gorm:"primary_key;type:uuid"`
	CreatedAt time.Time  `json:"-"`
	UpdatedAt time.Time  `json:"-"`
	DeletedAt *time.Time `json:"-"`

	//embed
	RoleInfo
	Permissions Permissions `json:"permissions,omitempty" gorm:"many2many:role_permissions"`
	Users       []*User     `json:"users,omitempty" gorm:"many2many:user_roles"`
}

type RoleSearch struct {
	//embed
	RoleInfo
	ContextContains string
	AllContexts     bool
	ServiceFilter   []string
	IDFilter        []string
	Permissions     bool
}

type Roles []Role
