/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"testing"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func Test_requestHandlerImpl_DeployAssetTag(t *testing.T) {
	var tagBytes = []byte("tHgfRQED1+pYgEZpq3dZC9ONmBCZKdx10LErTZs1k/k=")
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}

	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		tagWriteRequest *taModel.TagWriteRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Invalid Hardware uuid",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				tagWriteRequest: &taModel.TagWriteRequest{
					Tag:          tagBytes,
					HardwareUUID: "dad-2d82-49e4-9156-069b0065b262",
				},
			},
			wantErr: true,
		},
		{
			name: "Error creating tpm provider",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				tagWriteRequest: &taModel.TagWriteRequest{
					Tag:          tagBytes,
					HardwareUUID: "7a569dad-2d82-49e4-9156-069b0065b262",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			if err := handler.DeployAssetTag(tt.args.tagWriteRequest); (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.DeployAssetTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
