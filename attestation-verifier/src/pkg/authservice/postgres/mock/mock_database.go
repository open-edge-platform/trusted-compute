/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
)

type MockDatabase struct {
	MockUserStore       MockUserStore
	MockRoleStore       MockRoleStore
	MockPermissionStore MockPermissionStore
}

func (m *MockDatabase) Migrate() error {
	return nil
}

func (m *MockDatabase) UserStore() domain.UserStore {
	return &m.MockUserStore
}

func (m *MockDatabase) RoleStore() domain.RoleStore {
	return &m.MockRoleStore
}

func (m *MockDatabase) PermissionStore() domain.PermissionStore {
	return &m.MockPermissionStore
}

func (m *MockDatabase) Close() {

}
