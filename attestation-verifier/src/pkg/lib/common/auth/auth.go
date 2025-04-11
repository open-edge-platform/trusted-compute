/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package auth

import (
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"strings"
)

func ValidatePermissionAndGetRoleContext(privileges []types.RoleInfo, reqRoles []types.RoleInfo,
	retNilCtxForEmptyCtx bool) (*map[string]types.RoleInfo, bool) {

	ctx := make(map[string]types.RoleInfo)
	foundMatchingRole := false
	for _, role := range privileges {
		for _, reqRole := range reqRoles {
			if role.Service == reqRole.Service && role.Name == reqRole.Name {
				if strings.TrimSpace(role.Context) == "" && retNilCtxForEmptyCtx == true {
					return nil, true
				}
				if strings.TrimSpace(role.Context) != "" {
					ctx[strings.TrimSpace(role.Context)] = role
				}
				foundMatchingRole = true
			}
		}

	}
	return &ctx, foundMatchingRole
}

func ValidatePermissionAndGetPermissionsContext(privileges []types.PermissionInfo, reqPermissions types.PermissionInfo,
	retNilCtxForEmptyCtx bool) (*map[string]types.PermissionInfo, bool) {

	ctx := make(map[string]types.PermissionInfo)
	for _, permission := range privileges {
		if reqPermissions.Service == permission.Service {
			for _, rule := range permission.Rules {
				for _, reqRule := range reqPermissions.Rules {
					if isAuthorized(rule, reqRule) {
						if strings.TrimSpace(permission.Context) == "" && retNilCtxForEmptyCtx == true {
							return nil, true
						} else if strings.TrimSpace(permission.Context) != "" {
							ctx[strings.TrimSpace(permission.Context)] = permission
							return &ctx, true
						}
					}
				}
			}
		}
	}
	return &ctx, false
}

func isAuthorized(rule string, reqPermission string) bool {
	splitRule := strings.Split(rule, ":")
	splitReqPermission := strings.Split(reqPermission, ":")
	if len(splitRule) < 2 {
		return false
	}
	if len(splitRule) > 2 && splitRule[2] != "*" {
		return false
	}
	if (splitRule[0] == "*" || splitRule[0] == splitReqPermission[0]) && (splitRule[1] == "*" || splitRule[1] == splitReqPermission[1]) {
		return true
	} else {
		return false
	}
}
