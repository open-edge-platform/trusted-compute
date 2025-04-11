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

const (
	ValidPlatformInfoFile = "../test/resources/platform-info"
)

func Test_requestHandlerImpl_GetHostInfo(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	tests := []struct {
		name                 string
		fields               fields
		want                 *taModel.HostInfo
		platformInfoFilePath string
		wantErr              bool
	}{
		{
			name: "Invalid HostInfo file location",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			platformInfoFilePath: "",
			wantErr:              true,
		},
		{
			name: "GetHostInfo by reading hostinfo file",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			platformInfoFilePath: ValidPlatformInfoFile,
			wantErr:              false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			_, err := handler.GetHostInfo(tt.platformInfoFilePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.GetHostInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
