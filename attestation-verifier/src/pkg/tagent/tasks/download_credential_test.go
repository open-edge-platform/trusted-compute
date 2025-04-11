/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/stretchr/testify/assert"
)

func TestDownloadCredentialPrintHelp(t *testing.T) {
	type fields struct {
		Mode              string
		AasClientProvider aas.AasClientProvider
		HostId            string
		envPrefix         string
		commandName       string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print help for download credential",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadCredential{
				Mode:              tt.fields.Mode,
				AasClientProvider: tt.fields.AasClientProvider,
				HostId:            tt.fields.HostId,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestDownloadCredentialSetName(t *testing.T) {
	type fields struct {
		Mode              string
		AasClientProvider aas.AasClientProvider
		HostId            string
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
			name:   "Set name for download credential",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadCredential{
				Mode:              tt.fields.Mode,
				AasClientProvider: tt.fields.AasClientProvider,
				HostId:            tt.fields.HostId,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDownloadCredentialRun(t *testing.T) {

	mockAasClientProvider := NewMockAASClientFactory("")
	type fields struct {
		Mode              string
		AasClientProvider aas.AasClientProvider
		HostId            string
		envPrefix         string
		commandName       string
		NatsCredentials   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Download new credential",
			fields: fields{
				AasClientProvider: mockAasClientProvider,
				NatsCredentials:   "../test/resources/trust-agent.creds",
			},
			wantErr: false,
		},
		{
			name: "Fail to write file",
			fields: fields{
				AasClientProvider: mockAasClientProvider,
				NatsCredentials:   "credentials/trust-agent.creds",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadCredential{
				Mode:              tt.fields.Mode,
				AasClientProvider: tt.fields.AasClientProvider,
				HostId:            tt.fields.HostId,
				envPrefix:         tt.fields.envPrefix,
				commandName:       tt.fields.commandName,
				NatsCredentials:   tt.fields.NatsCredentials,
			}
			if err := task.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCredential.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := task.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadCredential.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	err := os.Remove("../test/resources/trust-agent.creds")
	assert.NoError(t, err)
}
