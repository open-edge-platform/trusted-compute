/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package context

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

func TestSetUserRoles(t *testing.T) {
	type args struct {
		r   *http.Request
		val []types.RoleInfo
	}

	r := &http.Request{}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "Validate SetUserRoles with valid data",
			args: args{
				r:   r,
				val: []types.RoleInfo{types.RoleInfo{Name: "test"}},
			},
			want: r.WithContext(context.WithValue(r.Context(), UserRoles, []types.RoleInfo{types.RoleInfo{Name: "test"}})),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SetUserRoles(tt.args.r, tt.args.val); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetUserRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetUserPermissions(t *testing.T) {
	type args struct {
		r   *http.Request
		val []types.PermissionInfo
	}
	r := &http.Request{}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "Validate SetUserPermissions with valid data",
			args: args{
				r:   r,
				val: []types.PermissionInfo{types.PermissionInfo{}},
			},
			want: r.WithContext(context.WithValue(r.Context(), UserPermissions, []types.PermissionInfo{types.PermissionInfo{}})),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SetUserPermissions(tt.args.r, tt.args.val); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetUserPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserRoles(t *testing.T) {
	type args struct {
		r *http.Request
	}
	r := &http.Request{}
	r = SetUserRoles(r, []types.RoleInfo{})
	r1 := &http.Request{}
	tests := []struct {
		name    string
		args    args
		want    []types.RoleInfo
		wantErr bool
	}{
		{
			name: "Validate GetUserRoless with valid data",
			args: args{
				r: r,
			},
			want:    []types.RoleInfo{},
			wantErr: false,
		},
		{
			name: "Validate GetUserRoless with invalid data",
			args: args{
				r: r1,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserRoles(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserRoles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUserRoles() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetUserPermissions(t *testing.T) {
	type args struct {
		r *http.Request
	}
	r := &http.Request{}
	r = SetUserPermissions(r, []types.PermissionInfo{})
	r1 := &http.Request{}
	tests := []struct {
		name    string
		args    args
		want    []types.PermissionInfo
		wantErr bool
	}{
		{
			name: "Validate GetUserPermissions with valid data",
			args: args{
				r: r,
			},
			want:    []types.PermissionInfo{},
			wantErr: false,
		},
		{
			name: "Validate GetUserPermissions with invalid data",
			args: args{
				r: r1,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetUserPermissions(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetUserPermissions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetUserPermissions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetTokenSubject(t *testing.T) {
	type args struct {
		r   *http.Request
		val string
	}
	r := &http.Request{}
	tests := []struct {
		name string
		args args
		want *http.Request
	}{
		{
			name: "Validate SetTokenSubject with valid data",
			args: args{
				r:   r,
				val: "test",
			},
			want: r.WithContext(context.WithValue(r.Context(), TokenSubject, "test")),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SetTokenSubject(tt.args.r, tt.args.val); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SetTokenSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetTokenSubject(t *testing.T) {
	type args struct {
		r *http.Request
	}
	r := &http.Request{}
	r = SetTokenSubject(r, "test")
	r1 := &http.Request{}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Validate GetTokenSubject with valid data",
			args: args{
				r: r,
			},
			want:    "test",
			wantErr: false,
		},
		{
			name: "Validate GetTokenSubject with invalid data",
			args: args{
				r: r1,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetTokenSubject(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTokenSubject() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetTokenSubject() = %v, want %v", got, tt.want)
			}
		})
	}
}
