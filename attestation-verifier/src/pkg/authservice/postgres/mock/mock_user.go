/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

type MockUserStore struct {
	CreateFunc      func(types.User) (*types.User, error)
	RetrieveFunc    func(types.User) (*types.User, error)
	RetrieveAllFunc func(types.User) (types.Users, error)
	UpdateFunc      func(types.User) error
	DeleteFunc      func(types.User) error
	UserStore       []types.User
	RoleStore       []types.Role
	PermissionStore []types.Permission
}

func (m *MockUserStore) Create(user types.User) (*types.User, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(user)
	}
	return nil, nil
}

func (m *MockUserStore) Retrieve(user types.User) (*types.User, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(user)
	}
	return nil, nil
}

func (m *MockUserStore) RetrieveAll(u types.User) (types.Users, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(u)
	}
	return nil, nil
}

func (m *MockUserStore) Update(user types.User) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(user)
	}
	return nil
}

func (m *MockUserStore) Delete(user types.User) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(user)
	}
	return nil
}

func (m *MockUserStore) GetUserRoleByID(u types.User, roleID string) (types.Role, error) {
	for _, user := range m.UserStore {
		if u.ID == user.ID && user.Roles == nil {
			return types.Role{}, errors.New("failed to GetUserRoleByID")
		}
	}
	for _, role := range m.RoleStore {
		if role.ID == roleID && role.DeletedAt != nil {
			return types.Role{}, errors.New("failed to GetUserRoleByID")
		}
	}
	return types.Role{}, nil
}

func (m *MockUserStore) GetRoles(user types.User, rs *types.RoleSearch, includeID bool) ([]types.Role, error) {
	for _, u := range m.UserStore {
		if (u.Name == user.Name || u.ID == user.ID) && u.DeletedAt != nil {
			return nil, errors.New("Unable to retrieve roles")
		}
		if (u.Name == user.Name || u.ID == user.ID) && u.Roles != nil {
			return u.Roles, nil
		}
	}
	return nil, nil
}

func (m *MockUserStore) GetPermissions(user types.User, rs *types.RoleSearch) ([]ct.PermissionInfo, error) {
	for _, u := range m.UserStore {
		if (u.Name == user.Name || u.ID == user.ID) && (u.Roles == nil || u.DeletedAt != nil) {
			return nil, errors.New("Unable to get permission")
		}
	}
	return nil, nil
}

func (m *MockUserStore) AddRoles(u types.User, roleList types.Roles, mustAddAllRoles bool) error {
	for index, user := range m.UserStore {
		if u.Name == user.Name || u.ID == user.ID {
			m.UserStore[index].Roles = roleList
		}
		if (u.Name == user.Name || u.ID == user.ID) && u.DeletedAt != nil {
			return errors.New("failed to add role(s)")
		}
	}
	return nil
}

func (m *MockUserStore) DeleteRole(u types.User, roleID string, svcFltr []string) error {
	var found bool
	for _, role := range m.RoleStore {
		if role.ID == roleID {
			found = true
			break
		}
	}
	for _, role := range m.RoleStore {
		if (role.ID == roleID) && role.DeletedAt != nil {
			return errors.New("failed to delete role")
		}
	}
	if !found {
		return errors.New("record not found")
	}
	return nil
}
