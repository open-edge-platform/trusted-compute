/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
)

type MockRoleStore struct {
	CreateFunc      func(types.Role) (*types.Role, error)
	RetrieveFunc    func(*types.RoleSearch) (*types.Role, error)
	RetrieveAllFunc func(*types.RoleSearch) (types.Roles, error)
	UpdateFunc      func(types.Role) error
	DeleteFunc      func(types.Role) error
}

func (m *MockRoleStore) Create(role types.Role) (*types.Role, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(role)
	}
	return nil, nil
}

func (m *MockRoleStore) Retrieve(rs *types.RoleSearch) (*types.Role, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(rs)
	}
	return nil, nil
}

func (m *MockRoleStore) RetrieveAll(rs *types.RoleSearch) (types.Roles, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(rs)
	}
	return nil, nil
}

func (m *MockRoleStore) Update(role types.Role) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(role)
	}
	return nil
}

func (m *MockRoleStore) Delete(role types.Role) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(role)
	}
	return nil
}
