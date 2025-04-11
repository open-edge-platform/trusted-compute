/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

func TestUpdateServiceConfig_Run(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	config := &config.Configuration{}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case - update service config",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "Username not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "Password not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "AASApiUrl not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AppConfig:     &config,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_SetName(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
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
			name: "Set name",
			args: args{
				n: "",
				e: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{}
			uc.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestUpdateServiceConfig_Validate(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	configValid := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidUsername := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidPassword := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidUrl := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		Server: commConfig.ServerConfig{
			Port: 1234,
		},
	}
	configWithInvalidPort := &config.Configuration{
		HVS: commConfig.ServiceConfig{
			Username: "Test",
			Password: "Test",
		},
		AASApiUrl: "Test",
		Server: commConfig.ServerConfig{
			Port: 1023,
		},
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case- validate successfully",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configValid,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "Username not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidUsername,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "Password not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidPassword,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "AASAPIUrl not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidUrl,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
		{
			name: "port not set",
			fields: fields{
				ServiceConfig: commConfig.ServiceConfig{
					Username: "Test",
					Password: "Test",
				},
				AASApiUrl:     "Test",
				AppConfig:     &configWithInvalidPort,
				ServerConfig:  commConfig.ServerConfig{},
				DefaultPort:   1234,
				NatServers:    "Test",
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			if err := uc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("UpdateServiceConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUpdateServiceConfig_PrintHelp(t *testing.T) {
	type fields struct {
		ServiceConfig commConfig.ServiceConfig
		AASApiUrl     string
		AppConfig     **config.Configuration
		ServerConfig  commConfig.ServerConfig
		DefaultPort   int
		NatServers    string
		ConsoleWriter io.Writer
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:  " Print help statement",
			wantW: "Following environment variables are required for update-service-config setup:\n    AAS_BASE_URL\t\t\t\tAAS Base URL\n    ENABLE_EKCERT_REVOKE_CHECK\t\t\tIf enabled, revocation checks will be performed for EK certs at the time of AIK provisioning\n    FVS_NUMBER_OF_DATA_FETCHERS\t\t\tNumber of Flavor verification data fetcher threads\n    FVS_NUMBER_OF_VERIFIERS\t\t\tNumber of Flavor verification verifier threads\n    FVS_SKIP_FLAVOR_SIGNATURE_VERIFICATION\tSkips flavor signature verification when set to true\n    HOST_TRUST_CACHE_THRESHOLD\t\t\tMaximum number of entries to be cached in the Trust/Flavor caches\n    HRRS_REFRESH_PERIOD\t\t\t\tHost report refresh service period\n    IMA_MEASURE_ENABLED\t\t\t\tTo enable Ima-Measure support in hvs\n    LOG_ENABLE_STDOUT\t\t\t\tEnable console log\n    LOG_LEVEL\t\t\t\t\tLog level\n    LOG_MAX_LENGTH\t\t\t\tMax length of log statement\n    NAT_SERVERS\t\t\t\t\tList of NATs servers to establish connection with outbound TAs\n    SERVER_IDLE_TIMEOUT\t\t\t\tRequest Idle Timeout in Seconds\n    SERVER_MAX_HEADER_BYTES\t\t\tMax Length of Request Header in Bytes\n    SERVER_PORT\t\t\t\t\tThe Port on which Server listens to\n    SERVER_READ_HEADER_TIMEOUT\t\t\tRequest Read Header Timeout Duration in Seconds\n    SERVER_READ_TIMEOUT\t\t\t\tRequest Read Timeout Duration in Seconds\n    SERVER_WRITE_TIMEOUT\t\t\tRequest Write Timeout Duration in Seconds\n    SERVICE_PASSWORD\t\t\t\tThe service password as configured in AAS\n    SERVICE_USERNAME\t\t\t\tThe service username as configured in AAS\n    VCSS_REFRESH_PERIOD\t\t\t\tVCenter refresh service period\n\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			uc := UpdateServiceConfig{
				ServiceConfig: tt.fields.ServiceConfig,
				AASApiUrl:     tt.fields.AASApiUrl,
				AppConfig:     tt.fields.AppConfig,
				ServerConfig:  tt.fields.ServerConfig,
				DefaultPort:   tt.fields.DefaultPort,
				NatServers:    tt.fields.NatServers,
				ConsoleWriter: tt.fields.ConsoleWriter,
			}
			w := &bytes.Buffer{}
			uc.PrintHelp(w)
			gotW := w.String()
			if gotW != tt.wantW {
				t.Errorf("UpdateServiceConfig.PrintHelp() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
