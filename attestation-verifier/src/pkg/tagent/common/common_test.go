/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"reflect"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func TestEndpointError_Error(t *testing.T) {
	type fields struct {
		Message    string
		StatusCode int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Mismatch message error",
			fields: fields{
				Message:    "hello",
				StatusCode: 1,
			},
			want: "1: hello",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := EndpointError{
				Message:    tt.fields.Message,
				StatusCode: tt.fields.StatusCode,
			}
			if got := e.Error(); got != tt.want {
				t.Errorf("EndpointError.Error() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRequestHandler(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type args struct {
		cfg *config.TrustAgentConfiguration
	}
	tests := []struct {
		name string
		args args
		want RequestHandler
	}{
		{
			name: "Create NewRequestHandler",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			want: &requestHandlerImpl{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewRequestHandler(tt.args.cfg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewRequestHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}
