/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package context

import (
	"context"
	"fmt"
	"net/http"

	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

const (
	UserRoles       = "userroles"
	UserPermissions = "userpermissions"
	TokenSubject    = "tokensubject"
)

func SetUserRoles(r *http.Request, val []types.RoleInfo) *http.Request {

	ctx := context.WithValue(r.Context(), UserRoles, val)
	return r.WithContext(ctx)
}

func SetUserPermissions(r *http.Request, val []types.PermissionInfo) *http.Request {

	ctx := context.WithValue(r.Context(), UserPermissions, val)
	return r.WithContext(ctx)
}

func GetUserRoles(r *http.Request) ([]types.RoleInfo, error) {
	if rv := r.Context().Value(UserRoles); rv != nil {
		if ur, ok := rv.([]types.RoleInfo); ok {
			return ur, nil
		}
	}
	return nil, fmt.Errorf("could not retrieve user roles from context")
}

func GetUserPermissions(r *http.Request) ([]types.PermissionInfo, error) {
	if rv := r.Context().Value(UserPermissions); rv != nil {
		if ur, ok := rv.([]types.PermissionInfo); ok {
			return ur, nil
		}
	}
	return nil, fmt.Errorf("could not retrieve user permissions from context")
}

func SetTokenSubject(r *http.Request, val string) *http.Request {

	ctx := context.WithValue(r.Context(), TokenSubject, val)
	return r.WithContext(ctx)
}

func GetTokenSubject(r *http.Request) (string, error) {
	if rv := r.Context().Value(TokenSubject); rv != nil {
		if ur, ok := rv.(string); ok {
			return ur, nil
		}
	}
	return "", fmt.Errorf("could not retrieve token subject from context")
}
