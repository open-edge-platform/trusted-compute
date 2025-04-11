/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_downloadRootCaCertificate(t *testing.T) {
	type args struct {
		cmsBaseUrl           string
		dirPath              string
		trustedTlsCertDigest string
		client               HttpClient
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate downloadRootCaCertificate with for client",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("200"),
			},
			wantErr: false,
		},
		{
			name: "Validate downloadRootCaCertificate with empty client",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               nil,
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid status code",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("400"),
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid tls",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("Invalid tls"),
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid cms url",
			args: args{
				cmsBaseUrl:           "#&!@*()/<>%/",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("200"),
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid tlscertdigest",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("200"),
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid dir path",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "Test%@$?/\\",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("200"),
			},
			wantErr: true,
		},
		{
			name: "Validate downloadRootCaCertificate with invalid body content",
			args: args{
				cmsBaseUrl:           "127.0.0.1/cms/v1",
				dirPath:              "",
				trustedTlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				client:               NewClientMock("Invalid body content"),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := downloadRootCaCertificate(tt.args.cmsBaseUrl, tt.args.dirPath, tt.args.trustedTlsCertDigest, tt.args.client); (err != nil) != tt.wantErr {
				t.Errorf("downloadRootCaCertificate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadCMSCert_Run(t *testing.T) {
	type fields struct {
		CaCertDirPath string
		CmsBaseURL    string
		TlsCertDigest string
		ConsoleWriter io.Writer
		commandName   string
		Client        HttpClient
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Download valid CMS Cert with valid client code",
			fields: fields{
				CaCertDirPath: "",
				CmsBaseURL:    "127.0.0.1/cms/v1",
				TlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				ConsoleWriter: os.Stdout,
				commandName:   "ls",
				Client:        NewClientMock("200"),
			},
			wantErr: false,
		},
		{
			name: "Download CMS Cert with invalid client code",
			fields: fields{
				CaCertDirPath: "",
				CmsBaseURL:    "127.0.0.1/cms/v1",
				TlsCertDigest: "b713b3bc413f39c02e188c3521c029e62b31ea4436d4e7bbb0757d03fde1e4ac64c567563ffa6c97bd51e0f0a4b672b4",
				ConsoleWriter: os.Stdout,
				commandName:   "ls",
				Client:        nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &DownloadCMSCert{
				CaCertDirPath: tt.fields.CaCertDirPath,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				TlsCertDigest: tt.fields.TlsCertDigest,
				ConsoleWriter: tt.fields.ConsoleWriter,
				commandName:   tt.fields.commandName,
				Client:        tt.fields.Client,
			}
			if err := cc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCMSCert.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadCMSCert_Validate(t *testing.T) {
	type fields struct {
		CaCertDirPath string
		CmsBaseURL    string
		TlsCertDigest string
		ConsoleWriter io.Writer
		commandName   string
		Client        HttpClient
	}
	err := os.Mkdir("Test", os.ModePerm)

	assert.NoError(t, err)

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate DownloadCMSCert with Valid cert path",
			fields: fields{
				CaCertDirPath: "../setup",
			},
			wantErr: false,
		},
		{
			name: "Validate DownloadCMSCert with invalid cert path",
			fields: fields{
				CaCertDirPath: "",
			},
			wantErr: true,
		},
		{
			name: "Validate DownloadCMSCert with invalid cert",
			fields: fields{
				CaCertDirPath: "Test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &DownloadCMSCert{
				CaCertDirPath: tt.fields.CaCertDirPath,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				TlsCertDigest: tt.fields.TlsCertDigest,
				ConsoleWriter: tt.fields.ConsoleWriter,
				commandName:   tt.fields.commandName,
				Client:        tt.fields.Client,
			}
			if err := cc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCMSCert.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("Test")
}
