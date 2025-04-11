/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"bytes"
	"crypto/x509/pkix"
	"io"
	"os"
	"testing"
)

func TestDownloadCert_Run(t *testing.T) {
	type fields struct {
		KeyFile       string
		CertFile      string
		KeyAlgorithm  string
		KeyLength     int
		Subject       pkix.Name
		SanList       string
		CertType      string
		CaCertDirPath string
		Client        HttpClient
		CmsBaseURL    string
		BearerToken   string
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "DownloadCert new certificate with valid cert",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/test.pem",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: false,
		},
		{
			name: "DownloadCert new certificate with valid test data",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: false,
		},
		{
			name: "DownloadCert new certificate with invalid status code",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("400"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid body content",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("Invalid body content"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid cert file",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/#%/",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with empty cms url",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/#%/",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid cms url",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "test #/\\!@#$%^&*()_",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid bearer token",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/#%/",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid client",
			fields: fields{
				KeyFile:       "e36663d78.pem",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/test.pem",
				SanList:       "127.0.0.1,hostname",
				Client:        nil,
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
		{
			name: "DownloadCert new certificate with invalid key file",
			fields: fields{
				KeyFile:       "/",
				CaCertDirPath: "test_data",
				CertFile:      "test_data/test.pem",
				SanList:       "127.0.0.1,hostname",
				Client:        NewClientMock("200"),
				CmsBaseURL:    "https://127.0.0.1:8445/v1/cms",
				BearerToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DownloadCert{
				KeyFile:       tt.fields.KeyFile,
				CertFile:      tt.fields.CertFile,
				KeyAlgorithm:  tt.fields.KeyAlgorithm,
				KeyLength:     tt.fields.KeyLength,
				Subject:       tt.fields.Subject,
				SanList:       tt.fields.SanList,
				CertType:      tt.fields.CertType,
				CaCertDirPath: tt.fields.CaCertDirPath,
				Client:        tt.fields.Client,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				BearerToken:   tt.fields.BearerToken,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := dc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCert.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadCert_Validate(t *testing.T) {
	type fields struct {
		KeyFile       string
		CertFile      string
		KeyAlgorithm  string
		KeyLength     int
		Subject       pkix.Name
		SanList       string
		CertType      string
		CaCertDirPath string
		Client        HttpClient
		CmsBaseURL    string
		BearerToken   string
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate certificate with valid keyfile",
			fields: fields{
				KeyFile: "test_data/e36663d78.pem",
			},
			wantErr: false,
		},
		{
			name: "Validate certificate with invalid keyfile",
			fields: fields{
				KeyFile: "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dc := &DownloadCert{
				KeyFile:       tt.fields.KeyFile,
				CertFile:      tt.fields.CertFile,
				KeyAlgorithm:  tt.fields.KeyAlgorithm,
				KeyLength:     tt.fields.KeyLength,
				Subject:       tt.fields.Subject,
				SanList:       tt.fields.SanList,
				CertType:      tt.fields.CertType,
				CaCertDirPath: tt.fields.CaCertDirPath,
				Client:        tt.fields.Client,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				BearerToken:   tt.fields.BearerToken,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := dc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCert.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadCert_SetName(t *testing.T) {
	type fields struct {
		KeyFile       string
		CertFile      string
		KeyAlgorithm  string
		KeyLength     int
		Subject       pkix.Name
		SanList       string
		CertType      string
		CaCertDirPath string
		Client        HttpClient
		CmsBaseURL    string
		BearerToken   string
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Set name for new certificate",
			args: args{
				n: "download-cert-tls",
				e: "-help",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DownloadCert{
				KeyFile:       tt.fields.KeyFile,
				CertFile:      tt.fields.CertFile,
				KeyAlgorithm:  tt.fields.KeyAlgorithm,
				KeyLength:     tt.fields.KeyLength,
				Subject:       tt.fields.Subject,
				SanList:       tt.fields.SanList,
				CertType:      tt.fields.CertType,
				CaCertDirPath: tt.fields.CaCertDirPath,
				Client:        tt.fields.Client,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				BearerToken:   tt.fields.BearerToken,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			tr.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDownloadCert_PrintHelp(t *testing.T) {
	type fields struct {
		KeyFile       string
		CertFile      string
		KeyAlgorithm  string
		KeyLength     int
		Subject       pkix.Name
		SanList       string
		CertType      string
		CaCertDirPath string
		Client        HttpClient
		CmsBaseURL    string
		BearerToken   string
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{
			name: "Help for download-cert-tls",
			fields: fields{
				commandName:   "download-cert-tls",
				ConsoleWriter: os.Stdout,
			},
		},
		{
			name: "Help for download-cert-saml",
			fields: fields{
				commandName:   "download-cert-saml",
				ConsoleWriter: os.Stdout,
			},
		},
		{
			name: "Invalid help input",
			fields: fields{
				commandName:   "Invalid command",
				ConsoleWriter: os.Stdout,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DownloadCert{
				KeyFile:       tt.fields.KeyFile,
				CertFile:      tt.fields.CertFile,
				KeyAlgorithm:  tt.fields.KeyAlgorithm,
				KeyLength:     tt.fields.KeyLength,
				Subject:       tt.fields.Subject,
				SanList:       tt.fields.SanList,
				CertType:      tt.fields.CertType,
				CaCertDirPath: tt.fields.CaCertDirPath,
				Client:        tt.fields.Client,
				CmsBaseURL:    tt.fields.CmsBaseURL,
				BearerToken:   tt.fields.BearerToken,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			tr.PrintHelp(w)
		})
	}
}

var downloadCertlsHelp = ` Following environment variables are required in download-cert-tls
BEARER_TOKEN	Bearer token for accessing CMS api
CMS_BASE_URL	CMS base URL in the format https://{{cms}}:{{cms_port}}/cms/v1/
SAN_LIST	Comma separated list of hostnames to add to Certificate, including IP addresses and DNS names

Following environment variables are optionally used in download-cert-tls
CERT_FILE		The file to which certificate is saved
COMMON_NAME		The common name of signed certificate
KEY_FILE		The file to which private key is saved`
