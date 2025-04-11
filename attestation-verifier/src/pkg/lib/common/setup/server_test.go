/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"io"
	"testing"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

func TestServerSetup_Run(t *testing.T) {
	type fields struct {
		ServerConfig  commConfig.ServerConfig
		SvrConfigPtr  *commConfig.ServerConfig
		ConsoleWriter io.Writer
		DefaultPort   int
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate server setup with valid data",
			fields: fields{
				SvrConfigPtr: &commConfig.ServerConfig{},
			},
			wantErr: false,
		},
		{
			name: "Validate server setup with invalid data",
			fields: fields{
				SvrConfigPtr: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &ServerSetup{
				ServerConfig:  tt.fields.ServerConfig,
				SvrConfigPtr:  tt.fields.SvrConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				DefaultPort:   tt.fields.DefaultPort,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := tr.Run(); (err != nil) != tt.wantErr {
				t.Errorf("ServerSetup.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestServerSetup_Validate(t *testing.T) {
	type fields struct {
		ServerConfig  commConfig.ServerConfig
		SvrConfigPtr  *commConfig.ServerConfig
		ConsoleWriter io.Writer
		DefaultPort   int
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate server setup with valid port",
			fields: fields{
				SvrConfigPtr: &commConfig.ServerConfig{
					Port: 1024,
				},
			},
			wantErr: false,
		},
		{
			name: "Validate server setup when config map not provided",
			fields: fields{
				SvrConfigPtr: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate server setup with invalid port",
			fields: fields{
				SvrConfigPtr: &commConfig.ServerConfig{
					Port: 1023,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &ServerSetup{
				ServerConfig:  tt.fields.ServerConfig,
				SvrConfigPtr:  tt.fields.SvrConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				DefaultPort:   tt.fields.DefaultPort,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := tr.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ServerSetup.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
