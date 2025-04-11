/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package aas

import (
	"net/http"

	aasTypes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/stretchr/testify/mock"
)

func NewMockAASClient() *MockAasClient {
	mockAasClient := MockAasClient{}
	return &mockAasClient
}

type MockAasClient struct {
	mock.Mock
}

func (c *MockAasClient) PrepReqHeader(req *http.Request) {
}

func (c *MockAasClient) CreateUser(u types.UserCreate) (*types.UserCreateResponse, error) {
	args := c.Called(u)
	return args.Get(0).(*types.UserCreateResponse), args.Error(1)
}

func (c *MockAasClient) GetUsers(name string) ([]types.UserCreateResponse, error) {
	args := c.Called(name)
	return args.Get(0).([]types.UserCreateResponse), args.Error(1)
}

func (c *MockAasClient) CreateRole(r types.RoleCreate) (*types.RoleCreateResponse, error) {
	args := c.Called(r)
	return args.Get(0).(*types.RoleCreateResponse), args.Error(1)
}

func (c *MockAasClient) AddRoleToUser(userID string, r types.RoleIDs) error {
	args := c.Called(userID, r)
	return args.Error(0)
}

func (c *MockAasClient) GetRoles(service, name, context, contextContains string, allContexts bool) (aasTypes.Roles, error) {
	args := c.Called(service, name, context, contextContains, allContexts)
	return args.Get(0).(aasTypes.Roles), args.Error(1)
}

func (c *MockAasClient) DeleteRole(roleId string) error {
	args := c.Called(roleId)
	return args.Error(0)
}

func (c *MockAasClient) GetPermissionsForUser(userID string) ([]types.PermissionInfo, error) {
	args := c.Called(userID)
	return args.Get(0).([]types.PermissionInfo), args.Error(1)
}

func (c *MockAasClient) GetRolesForUser(userID string) ([]types.RoleInfo, error) {
	args := c.Called(userID)
	return args.Get(0).([]types.RoleInfo), args.Error(1)
}

func (c *MockAasClient) UpdateUser(userID string, user types.UserCreate) error {
	args := c.Called(userID, user)
	return args.Error(0)
}

func (c *MockAasClient) GetCredentials(createCredentailsReq types.CreateCredentialsReq) ([]byte, error) {
	args := c.Called(createCredentailsReq)
	return args.Get(0).([]byte), args.Error(1)
}

func (c *MockAasClient) GetCustomClaimsToken(customClaimsTokenReq types.CustomClaims) ([]byte, error) {
	args := c.Called(customClaimsTokenReq)
	return args.Get(0).([]byte), args.Error(1)
}

func (c *MockAasClient) GetJwtSigningCertificate() ([]byte, error) {
	args := c.Called()
	return args.Get(0).([]byte), args.Error(1)
}
