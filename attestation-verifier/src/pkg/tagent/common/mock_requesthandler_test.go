/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func TestNewMockRequestHandler(t *testing.T) {
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
			name: "Create NewMockRequestHandler",
			args: args{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			want: &MockRequestHandlerImpl{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewMockRequestHandler(tt.args.cfg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewMockRequestHandler() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockRequestHandlerImpl_GetTpmQuote(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		quoteRequest *taModel.TpmQuoteRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *taModel.TpmQuoteResponse
		wantErr bool
	}{
		{
			name: "GetTpmQuote by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				quoteRequest: nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "httptest mode failed for GetTpmQuote",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			args: args{
				quoteRequest: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := m.GetTpmQuote(tt.args.quoteRequest, "", "", "")
			if (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.GetTpmQuote() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockRequestHandlerImpl.GetTpmQuote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockRequestHandlerImpl_GetHostInfo(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		in0 string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *taModel.HostInfo
		wantErr bool
	}{
		{
			name: "GetHostInfo by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				in0: "",
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "httptest mode failed for GetHostInfo",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			args: args{
				in0: "",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := m.GetHostInfo(tt.args.in0)
			if (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.GetHostInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockRequestHandlerImpl.GetHostInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockRequestHandlerImpl_GetAikDerBytes(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	tests := []struct {
		name        string
		fields      fields
		aikCertPath string
		want        []byte
		wantErr     bool
	}{
		{
			name: "GetAikDerBytes by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "httptest mode failed for GetAikDerBytes",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := m.GetAikDerBytes(tt.aikCertPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.GetAikDerBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockRequestHandlerImpl.GetAikDerBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockRequestHandlerImpl_DeployAssetTag(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		in0 *taModel.TagWriteRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "DeployAssetTag by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				in0: nil,
			},
			wantErr: false,
		},
		{
			name: "httptest mode failed for DeployAssetTag",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			args: args{
				in0: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			if err := m.DeployAssetTag(tt.args.in0); (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.DeployAssetTag() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMockRequestHandlerImpl_GetBindingCertificateDerBytes(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	os.MkdirAll(BindingKeyCertificateDir, os.ModePerm)
	CreateTestFile(BindingKeyCertificateDir, RootCert, "bindingkey.pem")
	defer DeleteCommonDir(BindingKeyCertificateDir)
	tests := []struct {
		name                      string
		fields                    fields
		want                      []byte
		wantErr                   bool
		bindingKeyCertificatePath string
	}{
		{
			name: "GetBindingCertificateDerBytes by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			want:                      nil,
			wantErr:                   false,
			bindingKeyCertificatePath: filepath.Join(BindingKeyCertificateDir, "bindingkey.pem"),
		},
		{
			name: "httptest mode failed for GetBindingCertificateDerBytes",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			want:                      nil,
			wantErr:                   true,
			bindingKeyCertificatePath: filepath.Join(BindingKeyCertificateDir, "bindingkey.pem"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := m.GetBindingCertificateDerBytes(tt.bindingKeyCertificatePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.GetBindingCertificateDerBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockRequestHandlerImpl.GetBindingCertificateDerBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMockRequestHandlerImpl_DeploySoftwareManifest(t *testing.T) {
	testVarDir := "../test/resources/opt/trustagent/var"
	os.MkdirAll(testVarDir, os.ModePerm)

	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		in0    *taModel.Manifest
		varDir string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "DeploySoftwareManifest by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				in0:    nil,
				varDir: testVarDir,
			},
			wantErr: false,
		},
		{
			name: "httptest mode failed for DeploySoftwareManifest",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			args: args{
				in0:    nil,
				varDir: testVarDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			if err := m.DeploySoftwareManifest(tt.args.in0, tt.args.varDir); (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.DeploySoftwareManifest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMockRequestHandlerImpl_GetApplicationMeasurement(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: tpmSecretKey}
	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		in0 *taModel.Manifest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *taModel.Measurement
		wantErr bool
	}{
		{
			name: "GetApplicationMeasurement by mocking",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				in0: nil,
			},
			wantErr: false,
		},
		{
			name: "httptest mode failed for GetApplicationMeasurement",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm:  tagValue,
					Mode: "httptest",
				},
			},
			args: args{
				in0: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MockRequestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			got, err := m.GetApplicationMeasurement(tt.args.in0, "../test/resources/", "../test/resources/")
			if (err != nil) != tt.wantErr {
				t.Errorf("MockRequestHandlerImpl.GetApplicationMeasurement() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MockRequestHandlerImpl.GetApplicationMeasurement() = %v, want %v", got, tt.want)
			}
		})
	}
}
