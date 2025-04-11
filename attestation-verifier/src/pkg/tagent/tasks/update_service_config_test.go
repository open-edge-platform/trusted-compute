/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

const (
	aasUrl = "https://aas.com:9443/aas/v1"
)

func TestUpdateServiceConfigPrintHelp(t *testing.T) {
	type fields struct {
		AppConfig     *config.TrustAgentConfiguration
		ServerConfig  commConfig.ServerConfig
		LoggingConfig commConfig.LogConfig
		AASApiUrl     string
		NatServers    config.NatsService
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print help for UpdateServiceConfig",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				LoggingConfig: tt.fields.LoggingConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				NatServers:    tt.fields.NatServers,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			uc.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestUpdateServiceConfigSetName(t *testing.T) {
	type fields struct {
		AppConfig     *config.TrustAgentConfiguration
		ServerConfig  commConfig.ServerConfig
		LoggingConfig commConfig.LogConfig
		AASApiUrl     string
		NatServers    config.NatsService
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
			name:   "Set name for UpdateServiceConfig",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := &UpdateServiceConfig{
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				LoggingConfig: tt.fields.LoggingConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				NatServers:    tt.fields.NatServers,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			uc.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestUpdateServiceConfigRun(t *testing.T) {
	type fields struct {
		AppConfig     *config.TrustAgentConfiguration
		ServerConfig  commConfig.ServerConfig
		LoggingConfig commConfig.LogConfig
		AASApiUrl     string
		NatServers    config.NatsService
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Invalid AAS URL",
			fields: fields{
				AASApiUrl: "`~!@#$%^&*()-=_+[]{}",
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: "",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Should update defaults",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Communication outbound mode failure case",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
					Mode: "outbound",
				},
			},
			wantErr: true,
		},
		{
			name: "Communication outbound mode pass case",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
					Mode: "outbound",
				},
				NatServers: config.NatsService{
					Servers: []string{"testserver1", "testserver2"},
					HostID:  "testHostID",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := &UpdateServiceConfig{
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				LoggingConfig: tt.fields.LoggingConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				NatServers:    tt.fields.NatServers,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := uc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfigValidate(t *testing.T) {
	type fields struct {
		AppConfig     *config.TrustAgentConfiguration
		ServerConfig  commConfig.ServerConfig
		LoggingConfig commConfig.LogConfig
		AASApiUrl     string
		NatServers    config.NatsService
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Empty AAS URL",
			fields: fields{
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: "",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Communication outbound mode pass case",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
					Mode: "outbound",
					Nats: config.NatsService{
						Servers: []string{"testserver1", "testserver2"},
						HostID:  "testId",
					},
				},
				NatServers: config.NatsService{
					Servers: []string{"testserver1", "testserver2"},
					HostID:  "testHostID",
				},
			},
			wantErr: false,
		},
		{
			name: "Communication outbound mode failure case",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
					Mode: "outbound",
				},
			},
			wantErr: true,
		},
		{
			name: "Communication http mode pass case",
			fields: fields{
				AASApiUrl: aasUrl,
				AppConfig: &config.TrustAgentConfiguration{
					Aas: config.AasConfig{
						BaseURL: aasUrl,
					},
					Mode: "http",
					Server: commConfig.ServerConfig{
						Port: 8081,
					},
					Nats: config.NatsService{
						Servers: []string{"testserver1", "testserver2"},
					},
				},
				NatServers: config.NatsService{
					Servers: []string{"testserver1", "testserver2"},
					HostID:  "testHostID",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := &UpdateServiceConfig{
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				LoggingConfig: tt.fields.LoggingConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				NatServers:    tt.fields.NatServers,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := uc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
