/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

type RoleInfo struct {
	Service string `json:"service"`
	// Name: UpdateHost
	Name string `json:"name" gorm:"not null"`
	// 1234-88769876-28768
	Context string `json:"context,omitempty"`
}

type PermissionInfo struct {
	Service string   `json:"service"`
	Context string   `json:"context,omitempty"`
	Rules   []string `json:"rules"`
}

type RoleCreate struct {
	RoleInfo             // embed
	Permissions []string `json:"permissions,omitempty"`
}

type RoleCreateResponse struct {
	Service string `json:"service"`
	Name    string `json:"name"`
	ID      string `json:"role_id"`
}

type RoleIDs struct {
	RoleUUIDs []string `json:"role_ids"`
}

type RoleSlice struct {
	Roles []RoleInfo `json:"roles"`
}

type UserCreate struct {
	Name     string `json:"username"`
	Password string `json:"password"`
}

type UserCreateResponse struct {
	ID   string `json:"user_id"`
	Name string `json:"username"`
}

type UserRoleCreate struct {
	ID      string `json:"user_id"`
	RoleIds RoleIDs
}

type UserCred struct {
	UserName string `json:"username"`
	Password string `json:"password"`
}

type PasswordChange struct {
	UserName        string `json:"username"`
	OldPassword     string `json:"old_password"`
	NewPassword     string `json:"new_password"`
	PasswordConfirm string `json:"password_confirm"`
}

type AuthClaims struct {
	Roles       []RoleInfo       `json:"roles"`
	Permissions []PermissionInfo `json:"permissions,omitempty"`
}

type CustomClaims struct {
	Subject      string                 `json:"subject"`
	ValiditySecs int                    `json:"validity_seconds"`
	Claims       map[string]interface{} `json:"claims"`
}

type CreateCredentialsReq struct {
	ComponentType string      `json:"type"`
	Parameters    *Parameters `json:"parameters,omitempty"`
}

type Parameters struct {
	TaHostId *string `json:"host-id,omitempty"`
}
