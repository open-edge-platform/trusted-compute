/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
)

type MockPermissionStore struct {
	CreateFunc      func(types.Permission) (*types.Permission, error)
	RetrieveFunc    func(*types.PermissionSearch) (*types.Permission, error)
	RetrieveAllFunc func(*types.PermissionSearch) (types.Permissions, error)
	UpdateFunc      func(types.Permission) error
	DeleteFunc      func(types.Permission) error
}

func (m *MockPermissionStore) Create(permission types.Permission) (*types.Permission, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(permission)
	}
	return nil, nil
}

func (m *MockPermissionStore) Retrieve(rs *types.PermissionSearch) (*types.Permission, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(rs)
	}
	return nil, nil
}

func (m *MockPermissionStore) RetrieveAll(rs *types.PermissionSearch) (types.Permissions, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(rs)
	}
	return nil, nil
}

func (m *MockPermissionStore) Update(permission types.Permission) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(permission)
	}
	return nil
}

func (m *MockPermissionStore) Delete(permission types.Permission) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(permission)
	}
	return nil
}
