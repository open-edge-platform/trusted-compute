/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"
)

const (
	RootCert = "../test/resources/root_cert_pem"
)

func CreateTestFile(destDir string, src string, fileName string) {
	os.MkdirAll(destDir, os.ModePerm)
	bytesRead, err := ioutil.ReadFile(src)
	if err != nil {
		log.Fatal(err)
	}

	dest := path.Join(destDir, fileName)
	err = ioutil.WriteFile(dest, bytesRead, os.ModePerm)
	if err != nil {
		log.Fatal(err)
	}
}

func DeleteCommonDir(destDir string) {
	os.RemoveAll(destDir)
}

func Test_requestHandlerImpl_GetAikDerBytes(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	DeleteCommonDir(testConfigDir)

	CreateTestFile(testConfigDir, "../test/resources/platform-info", "invalidAik.pem")
	CreateTestFile(testConfigDir, RootCert, "validAik.pem")

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
			name: "Aik cert file does not exist",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid  Aik cert file",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			aikCertPath: filepath.Join(testConfigDir, "invalidAik.pem"),
			wantErr:     true,
		},
		{
			name: "GetAikDerBytes from Aik cert file",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			aikCertPath: filepath.Join(testConfigDir, "validAik.pem"),
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			_, err := handler.GetAikDerBytes(tt.aikCertPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.GetAikDerBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	DeleteCommonDir(testConfigDir)
}

func TestGetAikPem(t *testing.T) {
	CreateTestFile(testConfigDir, RootCert, "aik.pem")
	tests := []struct {
		name        string
		want        []byte
		aikCertPath string
		wantErr     bool
	}{
		{
			name:    "Aik cert file does not exist",
			wantErr: true,
		},
		{
			name:        "GetAikPem cert from Aik file",
			aikCertPath: filepath.Join(testConfigDir, "aik.pem"),
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "GetAikPem cert from Aik file" {
				CreateTestFile(testConfigDir, RootCert, "aik.pem")
			}
			_, err := GetAikPem(tt.aikCertPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAikPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	DeleteCommonDir(testConfigDir)
}
