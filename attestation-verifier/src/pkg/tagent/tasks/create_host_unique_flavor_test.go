/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateHostUniqueFlavorPrintHelp(t *testing.T) {

	cliFactory, _ := hvsclient.NewVSClientFactory("baseurl", "token", "../test/mockCACertsDir")

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
			name: "Print help for CreateHostUniqueFlavor",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 8400,
				AppConfig:      &config.TrustAgentConfiguration{},
				ClientFactory:  cliFactory,
			},
			wantW: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHostUniqueFlavor{
				AppConfig:      tt.fields.AppConfig,
				ClientFactory:  tt.fields.ClientFactory,
				TrustAgentPort: tt.fields.TrustAgentPort,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
		})
	}
}

func TestCreateHostUniqueFlavorSetName(t *testing.T) {

	cliFactory, _ := hvsclient.NewVSClientFactory("baseurl", "token", "../test/mockCACertsDir")

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
			name: "Set name for CreateHostUniqueFlavor",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 8400,
				AppConfig:      &config.TrustAgentConfiguration{},
				ClientFactory:  cliFactory,
			},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &CreateHostUniqueFlavor{
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

func TestCreateHostUniqueFlavorRun(t *testing.T) {

	cliFactorywithInvalidbaseurl, _ := hvsclient.NewVSClientFactory("baseurl", "token", "../test/mockCACertsDir")
	cliFactorywithValidbaseurl, _ := hvsclient.NewVSClientFactory("https://localhost:1443/v2", "token", "../test/mockCACertsDir")

	mockedFlavorsClient := new(hvsclient.MockedFlavorsClient)
	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	mockedFlavorsClient.On("CreateFlavor", mock.Anything).Return(hvs.FlavorCollection{}, nil)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedFlavorsClient: mockedFlavorsClient}

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
			name: "Unable to create host unique flavor",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig:      &config.TrustAgentConfiguration{},
				ClientFactory:  cliFactorywithInvalidbaseurl,
			},
			wantErr: true,
		},
		{
			name: "No host id found",
			fields: fields{
				envPrefix:      ".test",
				commandName:    "test",
				TrustAgentPort: 1443,
				AppConfig: &config.TrustAgentConfiguration{
					Mode: "outbound",
				},
				ClientFactory: cliFactorywithValidbaseurl,
			},
			wantErr: true,
		},
		{
			name: "create new host unique flavor",
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
			task := &CreateHostUniqueFlavor{
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
				t.Errorf("CreateHostUniqueFlavor.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateHostUniqueFlavorValidate(t *testing.T) {

	mockedFlavorsClient := new(hvsclient.MockedFlavorsClient)
	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	mockedFlavorsClient.On("CreateFlavor", mock.Anything).Return(hvs.FlavorCollection{}, nil)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedFlavorsClient: mockedFlavorsClient}

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
			name: "Validate Outbound with host id",
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
			wantErr: false,
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
			wantErr: true,
		},
		{
			name: "Validate create host unique flavor",
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
			task := &CreateHostUniqueFlavor{
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
				t.Errorf("CreateHostUniqueFlavor.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
