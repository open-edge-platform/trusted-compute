/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package context

import (
	"context"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
)

type httpContextKey string

var userRoleKey = httpContextKey("userroles")

func SetUserRoles(r *http.Request, val types.Roles) *http.Request {

	ctx := context.WithValue(r.Context(), userRoleKey, val)
	return r.WithContext(ctx)
}

func GetUserRoles(r *http.Request) types.Roles {
	if rv := r.Context().Value(userRoleKey); rv != nil {
		return rv.(types.Roles)
	}
	return nil
}
