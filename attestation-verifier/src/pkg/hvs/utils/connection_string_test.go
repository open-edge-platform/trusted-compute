/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"testing"
)

func TestGetConnectionStringWithoutCredentials(t *testing.T) {
	type args struct {
		cs string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Valid Connection string without credentials",
			args: args{
				cs: "u=test;https:\\127.0.0.1\v1\ta",
			},
			want: "https:\\127.0.0.1\v1\ta",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetConnectionStringWithoutCredentials(tt.args.cs); got != tt.want {
				t.Errorf("GetConnectionStringWithoutCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConnectionString(t *testing.T) {
	type args struct {
		cs string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid connection string",
			args: args{
				cs: "intel:https://ta.ip.com:1443;u=admin;p=password",
			},
			wantErr: false,
		},
		{
			name: "Invalid username",
			args: args{
				cs: "intel:https://ta.ip.com:1443;u=admin();p=password",
			},
			wantErr: true,
		},
		{
			name: "Invalid hostname",
			args: args{
				cs: "intel:https://ta.ip.com:1443;u=admin;h=hostname();",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateConnectionString(tt.args.cs); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConnectionString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
