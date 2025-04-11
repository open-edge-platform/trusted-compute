/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
)

func Test_addDBUser(t *testing.T) {
	type args struct {
		db       domain.AASDatabase
		username string
		password string
		roles    []types.Role
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Invalid case with empty username",
			args: args{
				username: "",
			},
			wantErr: true,
		},
		{
			name: "Invalid case with empty password",
			args: args{
				username: "test",
				password: "",
			},
			wantErr: true,
		},
		{
			name: "Username Validation",
			args: args{
				username: "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM",
				password: "testPassword",
			},
			wantErr: true,
		},
		{
			name: "Passsword Validation",
			args: args{
				username: "testusername",
				password: "mVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM80zpCYoGznQkFklJR4pxDYsPbrmYBxsmVYf0dEtIDkPCi9FGI8wuwyGvKSqZotHw3xGQxUHIVdS3SIKKwqn0MQxnZYmGFSat5PTdmWilYozKRqw3kwoSRmxH7xhDOfcYQWbuRKIDhCE00Bf2raaoCg0Q0MyrVpBM",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := addDBUser(tt.args.db, tt.args.username, tt.args.password, tt.args.roles); (err != nil) != tt.wantErr {
				t.Errorf("addDBUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
