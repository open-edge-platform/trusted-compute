/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/stretchr/testify/mock"
)

func TestDownloadPrivacyCAPrintHelp(t *testing.T) {

	cliFactory, _ := hvsclient.NewVSClientFactory("baseurl", "token", "../test/mockCACertsDir")

	type fields struct {
		ClientFactory hvsclient.HVSClientFactory
		envPrefix     string
		commandName   string
		PrivacyCA     string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{

		{
			name: "Print help for download privacy CA",
			fields: fields{
				envPrefix:     ".test",
				commandName:   "test",
				PrivacyCA:     "../test/mockCACertsDir",
				ClientFactory: cliFactory,
			},
			wantW: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadPrivacyCA{
				ClientFactory: tt.fields.ClientFactory,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
				PrivacyCA:     tt.fields.PrivacyCA,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestDownloadPrivacyCASetName(t *testing.T) {

	cliFactory, _ := hvsclient.NewVSClientFactory("baseurl", "token", "../test/mockCACertsDir")

	type fields struct {
		ClientFactory hvsclient.HVSClientFactory
		envPrefix     string
		commandName   string
		PrivacyCA     string
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
			name: "Set name for download privacy CA",
			fields: fields{
				envPrefix:     ".test",
				commandName:   "test",
				PrivacyCA:     "../test/mockCACertsDir",
				ClientFactory: cliFactory,
			},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadPrivacyCA{
				ClientFactory: tt.fields.ClientFactory,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
				PrivacyCA:     tt.fields.PrivacyCA,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDownloadPrivacyCARun(t *testing.T) {

	mockedPrivacyCaClient := new(hvsclient.MockedPrivacyCAClient)
	mockedPrivacyCaClient.On("DownloadPrivacyCa", mock.Anything).Return([]uint8{}, nil)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedPrivacyCAClient: mockedPrivacyCaClient}

	type fields struct {
		ClientFactory hvsclient.HVSClientFactory
		envPrefix     string
		commandName   string
		PrivacyCA     string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "File write failure",
			fields: fields{
				envPrefix:     ".test",
				commandName:   "test",
				PrivacyCA:     "../test/mockCACertsDir",
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
		{
			name: "Download new privacy CA",
			fields: fields{
				envPrefix:     ".test",
				commandName:   "test",
				PrivacyCA:     "../test/mockCACertsDir/mocktestprivacyca.pem",
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadPrivacyCA{
				ClientFactory: tt.fields.ClientFactory,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
				PrivacyCA:     tt.fields.PrivacyCA,
			}
			if err := task.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadPrivacyCA.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDownloadPrivacyCAValidate(t *testing.T) {

	mockedPrivacyCaClient := new(hvsclient.MockedPrivacyCAClient)
	mockedPrivacyCaClient.On("DownloadPrivacyCa", mock.Anything).Return([]uint8{}, nil)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedPrivacyCAClient: mockedPrivacyCaClient}

	type fields struct {
		ClientFactory hvsclient.HVSClientFactory
		envPrefix     string
		commandName   string
		PrivacyCA     string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Failed to validate privacy CA",
			fields: fields{
				envPrefix:     ".test",
				commandName:   "test",
				PrivacyCA:     "../test/mockCACertsDir/mocktestprivacyca.pem",
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DownloadPrivacyCA{
				ClientFactory: tt.fields.ClientFactory,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
				PrivacyCA:     tt.fields.PrivacyCA,
			}
			if err := task.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DownloadPrivacyCA.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
