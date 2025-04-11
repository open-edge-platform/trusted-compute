/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

const (
	BindingKeyCertificateDir = "../test/resources/etc/workload-agent/"
)

func TestRequestHandlerImplGetBindingCertificateDerBytes(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	os.MkdirAll(BindingKeyCertificateDir, os.ModePerm)
	CreateTestFile(BindingKeyCertificateDir, RootCert, "bindingkey.pem")
	defer DeleteCommonDir(BindingKeyCertificateDir)

	tests := []struct {
		name                      string
		fields                    fields
		wantErr                   bool
		bindingKeyCertificatePath string
	}{
		{
			name: "BindingCertificate file does not exist",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			bindingKeyCertificatePath: "dir/not/exists",
			wantErr:                   true,
		},
		{
			name: "Valid BindingCertificate",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			bindingKeyCertificatePath: filepath.Join(BindingKeyCertificateDir, "bindingkey.pem"),
			wantErr:                   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			_, err := handler.GetBindingCertificateDerBytes(tt.bindingKeyCertificatePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.GetBindingCertificateDerBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
