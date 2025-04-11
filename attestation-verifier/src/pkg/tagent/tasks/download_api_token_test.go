/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

func TestDownloadApiTokenPrintHelp(t *testing.T) {
	type fields struct {
		Config            *config.TrustAgentConfiguration
		AasClientProvider aas.AasClientProvider
		envPrefix         string
		commandName       string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print help for download api token",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadApiToken{
				Config:            tt.fields.Config,
				AasClientProvider: tt.fields.AasClientProvider,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestDownloadApiTokenSetName(t *testing.T) {
	type fields struct {
		Config            *config.TrustAgentConfiguration
		AasClientProvider aas.AasClientProvider
		envPrefix         string
		commandName       string
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
			name:   "Setname for download api token",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadApiToken{
				Config:            tt.fields.Config,
				AasClientProvider: tt.fields.AasClientProvider,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDownloadApiTokenRun(t *testing.T) {

	mockAasClientProvider := NewMockAASClientFactory("downloadApiToken")

	type fields struct {
		Config            *config.TrustAgentConfiguration
		AasClientProvider aas.AasClientProvider
		envPrefix         string
		commandName       string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Download api token",
			fields: fields{
				Config:            &config.TrustAgentConfiguration{},
				AasClientProvider: mockAasClientProvider,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadApiToken{
				Config:            tt.fields.Config,
				AasClientProvider: tt.fields.AasClientProvider,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			task.Run()
		})
	}
}

func TestDownloadApiTokenValidate(t *testing.T) {
	type fields struct {
		Config            *config.TrustAgentConfiguration
		AasClientProvider aas.AasClientProvider
		envPrefix         string
		commandName       string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate download api token",
			fields: fields{
				Config: &config.TrustAgentConfiguration{
					ApiToken: "test token",
				},
			},
			wantErr: false,
		},
		{
			name: "Unable to validate download api token",
			fields: fields{
				Config: &config.TrustAgentConfiguration{
					ApiToken: "",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadApiToken{
				Config:            tt.fields.Config,
				AasClientProvider: tt.fields.AasClientProvider,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			if err := task.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadApiToken.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
