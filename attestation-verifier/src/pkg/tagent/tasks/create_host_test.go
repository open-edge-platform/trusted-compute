/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateHostPrintHelp(t *testing.T) {

	mockedHostClient := new(hvsclient.MockedHostsClient)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostClient}

	type fields struct {
		AppConfig      *config.TrustAgentConfiguration
		ClientFactory  hvsclient.HVSClientFactory
		TrustAgentPort int
		envPrefix      string
		commandName    string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "Print help data",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig:      &config.TrustAgentConfiguration{},
				ClientFactory:  mockedVSClientFactory,
			},
			wantW: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHost{
				AppConfig:      tt.fields.AppConfig,
				ClientFactory:  tt.fields.ClientFactory,
				TrustAgentPort: tt.fields.TrustAgentPort,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestCreateHostSetName(t *testing.T) {

	mockedHostClient := new(hvsclient.MockedHostsClient)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostClient}

	type fields struct {
		AppConfig      *config.TrustAgentConfiguration
		ClientFactory  hvsclient.HVSClientFactory
		TrustAgentPort int
		envPrefix      string
		commandName    string
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
			name: "Set name to create host",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 8400,
				AppConfig:      &config.TrustAgentConfiguration{},
				ClientFactory:  mockedVSClientFactory,
			},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHost{
				AppConfig:      tt.fields.AppConfig,
				ClientFactory:  tt.fields.ClientFactory,
				TrustAgentPort: tt.fields.TrustAgentPort,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestCreateHostRun(t *testing.T) {

	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{}}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	os.Setenv(constants.EnvBearerToken, bearerToken)

	type fields struct {
		AppConfig      *config.TrustAgentConfiguration
		ClientFactory  hvsclient.HVSClientFactory
		TrustAgentPort int
		envPrefix      string
		commandName    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "No host id provided",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "outbound",
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: false,
		},
		{
			name: "Create new host",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "http",
					Nats: config.NatsService{
						HostID: "1000",
					},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: false,
		},
		{
			name: "Client ip not found",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "http",
					Nats: config.NatsService{
						HostID: "1000",
					},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHost{
				AppConfig:      tt.fields.AppConfig,
				ClientFactory:  tt.fields.ClientFactory,
				TrustAgentPort: tt.fields.TrustAgentPort,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}

			if tt.name == "Client ip not found" {
				err := os.Unsetenv(constants.EnvCurrentIP)
				if err != nil {
					assert.NoError(t, err)
				}
			}

			if err := task.Run(); (err != nil) != tt.wantErr {
				t.Errorf("CreateHost.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateHostValidate(t *testing.T) {

	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{}}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	os.Setenv(constants.EnvBearerToken, bearerToken)

	type fields struct {
		AppConfig      *config.TrustAgentConfiguration
		ClientFactory  hvsclient.HVSClientFactory
		TrustAgentPort int
		envPrefix      string
		commandName    string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Unable to validate create host",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "outbound",
					Nats: config.NatsService{
						HostID: "1000",
					},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
		{
			name: "Outbound without host id",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "outbound",
					Nats: config.NatsService{},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: false,
		},
		{
			name: "Should fail in http mode",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "http",
					Nats: config.NatsService{
						HostID: "1000",
					},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
		{
			name: "Client ip not found",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "http",
					Nats: config.NatsService{
						HostID: "1000",
					},
				},
				ClientFactory: mockedVSClientFactory,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHost{
				AppConfig:      tt.fields.AppConfig,
				ClientFactory:  tt.fields.ClientFactory,
				TrustAgentPort: tt.fields.TrustAgentPort,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}

			if tt.name == "Client ip not found" {
				err := os.Unsetenv(constants.EnvCurrentIP)
				if err != nil {
					assert.NoError(t, err)
				}
			}

			if err := task.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateHost.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
