/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package auth

import (
	"testing"

	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

func TestValidatePermissionAndGetRoleContext(t *testing.T) {
	type args struct {
		privileges           []types.RoleInfo
		reqRoles             []types.RoleInfo
		retNilCtxForEmptyCtx bool
	}
	roles1 := types.RoleInfo{}
	roles2 := types.RoleInfo{}
	Privileges1 := []types.RoleInfo{}
	ReqRoles1 := []types.RoleInfo{}
	Privileges2 := []types.RoleInfo{}
	ReqRoles2 := []types.RoleInfo{}
	roles1 = types.RoleInfo{
		Service: "KBS",
		Name:    "createKey",
		Context: "1234-88769876-28768",
	}
	Privileges1 = append(Privileges1, roles1)
	ReqRoles1 = append(ReqRoles1, roles1)
	roles2 = types.RoleInfo{
		Service: "KBS",
		Name:    "createKey",
	}
	Privileges2 = append(Privileges2, roles2)
	ReqRoles2 = append(ReqRoles2, roles2)
	tests := []struct {
		name           string
		args           args
		want           *map[string]types.RoleInfo
		isMatchingRule bool
	}{
		{
			name: "Valid role with context",
			args: args{
				privileges: Privileges1,
				reqRoles:   ReqRoles1,
			},
			isMatchingRule: true,
		},
		{
			name: "Valid role without context",
			args: args{
				privileges:           Privileges2,
				reqRoles:             ReqRoles2,
				retNilCtxForEmptyCtx: true,
			},
			isMatchingRule: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got1 := ValidatePermissionAndGetRoleContext(tt.args.privileges, tt.args.reqRoles, tt.args.retNilCtxForEmptyCtx)
			if got1 != tt.isMatchingRule {
				t.Errorf("ValidatePermissionAndGetRoleContext() got1 = %v, want %v", got1, tt.isMatchingRule)
			}
		})
	}
}

func Test_isAuthorized(t *testing.T) {
	type args struct {
		rule          string
		reqPermission string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Valid rule with all permission",
			args: args{
				rule:          "*:*",
				reqPermission: "*:*",
			},
			want: true,
		},
		{
			name: "Invalid rule with kbs:search permission",
			args: args{
				rule:          "kbs:create",
				reqPermission: "kbs:search",
			},
			want: false,
		},
		{
			name: "Invalid rule with kbs permission",
			args: args{
				rule:          "kbs",
				reqPermission: "kbs",
			},
			want: false,
		},
		{
			name: "Invalid rule with invalid permission",
			args: args{
				rule:          "kbs:invalid:invalid",
				reqPermission: "kbs:invalid:invalid",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAuthorized(tt.args.rule, tt.args.reqPermission); got != tt.want {
				t.Errorf("isAuthorized() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePermissionAndGetPermissionsContext(t *testing.T) {
	type args struct {
		privileges           []types.PermissionInfo
		reqPermissions       types.PermissionInfo
		retNilCtxForEmptyCtx bool
	}
	privileges := []types.PermissionInfo{}
	reqPermissions := types.PermissionInfo{}
	reqPermissions = types.PermissionInfo{
		Service: "kbs",
		Context: "1234-88769876-28768",
		Rules:   []string{"kbs:create"},
	}
	privileges = append(privileges, reqPermissions)
	tests := []struct {
		name  string
		args  args
		want1 bool
	}{
		{
			name: "Valid permission with context",
			args: args{
				privileges:     privileges,
				reqPermissions: reqPermissions,
			},
			want1: true,
		},
		{
			name: "Valid permission without context",
			args: args{
				privileges: []types.PermissionInfo{types.PermissionInfo{Service: "kbs",
					Rules: []string{"kbs:create"}}},
				reqPermissions: types.PermissionInfo{Service: "kbs",
					Rules: []string{"kbs:create"}},
				retNilCtxForEmptyCtx: true,
			},
			want1: true,
		},
		{
			name: "Invalid permission",
			args: args{
				privileges:     []types.PermissionInfo{},
				reqPermissions: types.PermissionInfo{},
			},
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got1 := ValidatePermissionAndGetPermissionsContext(tt.args.privileges, tt.args.reqPermissions, tt.args.retNilCtxForEmptyCtx)
			if got1 != tt.want1 {
				t.Errorf("ValidatePermissionAndGetPermissionsContext() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
