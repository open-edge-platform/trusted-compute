/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package domain

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

type (
	AASDatabase interface {
		Migrate() error
		UserStore() UserStore
		RoleStore() RoleStore
		PermissionStore() PermissionStore
		Close()
	}

	PermissionStore interface {
		Create(types.Permission) (*types.Permission, error)
		Retrieve(*types.PermissionSearch) (*types.Permission, error)
		RetrieveAll(*types.PermissionSearch) (types.Permissions, error)
		Update(types.Permission) error
		Delete(types.Permission) error
	}

	RoleStore interface {
		Create(types.Role) (*types.Role, error)
		Retrieve(*types.RoleSearch) (*types.Role, error)
		RetrieveAll(*types.RoleSearch) (types.Roles, error)
		Update(types.Role) error
		Delete(types.Role) error
	}

	UserStore interface {
		Create(types.User) (*types.User, error)
		Retrieve(types.User) (*types.User, error)
		RetrieveAll(user types.User) (types.Users, error)
		Update(types.User) error
		Delete(types.User) error
		GetRoles(types.User, *types.RoleSearch, bool) ([]types.Role, error)
		GetPermissions(types.User, *types.RoleSearch) ([]ct.PermissionInfo, error)
		AddRoles(types.User, types.Roles, bool) error
		GetUserRoleByID(types.User, string) (types.Role, error)
		DeleteRole(types.User, string, []string) error
	}
)
