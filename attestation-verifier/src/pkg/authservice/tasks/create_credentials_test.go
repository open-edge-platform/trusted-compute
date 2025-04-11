/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"io"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
)

func TestCreateCredentials_Run(t *testing.T) {
	type fields struct {
		CreateCredentials bool
		NatsConfig        config.NatsConfig
		ConsoleWriter     io.Writer
	}
	tests := []struct {
		name                     string
		fields                   fields
		OperatorSeedFile         string
		AccountSeedFile          string
		AccountConfigurationFile string
		wantErr                  bool
	}{
		{
			name: "Validate with CREATE_CREDENTIALS set to false",
			fields: fields{
				CreateCredentials: false,
				NatsConfig:        config.NatsConfig{},
				ConsoleWriter:     os.Stdout,
			},
			wantErr: false,
		},
		{
			name: "Validate with CREATE_CREDENTIALS set to true",
			fields: fields{
				CreateCredentials: true,
				NatsConfig:        config.NatsConfig{},
				ConsoleWriter:     os.Stdout,
			},
			OperatorSeedFile:         "../../../test/aas/operator-seed.txt",
			AccountSeedFile:          "../../../test/aas/account-seed.txt",
			AccountConfigurationFile: "../../../test/aas/server.conf",
			wantErr:                  false,
		},
		{
			name: "Validate with Invalid OperatorSeedFile",
			fields: fields{
				CreateCredentials: true,
				NatsConfig:        config.NatsConfig{},
				ConsoleWriter:     os.Stdout,
			},
			OperatorSeedFile:         "",
			AccountSeedFile:          "../../../test/aas/account-seed.txt",
			AccountConfigurationFile: "../../../test/aas/server.conf",
			wantErr:                  true,
		},
		{
			name: "Validate with Invalid AccountSeedFile",
			fields: fields{
				CreateCredentials: true,
				NatsConfig:        config.NatsConfig{},
				ConsoleWriter:     os.Stdout,
			},
			OperatorSeedFile:         "../../../test/aas/operator-seed.txt",
			AccountSeedFile:          "",
			AccountConfigurationFile: "../../../test/aas/server.conf",
			wantErr:                  true,
		},
		{
			name: "Validate with Invalid AccountConfigurationFile",
			fields: fields{
				CreateCredentials: true,
				NatsConfig:        config.NatsConfig{},
				ConsoleWriter:     os.Stdout,
			},
			OperatorSeedFile:         "../../../test/aas/operator-seed.txt",
			AccountSeedFile:          "../../../test/aas/account-seed.txt",
			AccountConfigurationFile: "",
			wantErr:                  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &CreateCredentials{
				CreateCredentials:        tt.fields.CreateCredentials,
				NatsConfig:               tt.fields.NatsConfig,
				ConsoleWriter:            tt.fields.ConsoleWriter,
				OperatorSeedFile:         tt.OperatorSeedFile,
				AccountSeedFile:          tt.AccountSeedFile,
				AccountConfigurationFile: tt.AccountConfigurationFile,
			}
			if err := cc.Run(); (err != nil) != tt.wantErr {
				t.Errorf("CreateCredentials.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateCredentials_Validate(t *testing.T) {
	type fields struct {
		CreateCredentials        bool
		NatsConfig               config.NatsConfig
		ConsoleWriter            io.Writer
		OperatorSeedFile         string
		AccountSeedFile          string
		AccountConfigurationFile string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate with CreateCredentials set to false",
			fields: fields{
				CreateCredentials: false,
			},
			wantErr: false,
		},
		{
			name: "Validate with empty OperatorSeedFile name",
			fields: fields{
				CreateCredentials: true,
				OperatorSeedFile:  "",
			},
			wantErr: true,
		},
		{
			name: "Validate with empty AccountSeedFile name",
			fields: fields{
				CreateCredentials: true,
				OperatorSeedFile:  "../../../test/aas/operator-seed.txt",
				AccountSeedFile:   "",
			},
			wantErr: true,
		},
		{
			name: "Validate with empty AccountConfigurationFile name",
			fields: fields{
				CreateCredentials:        true,
				OperatorSeedFile:         "../../../test/aas/operator-seed.txt",
				AccountSeedFile:          "../../../test/aas/account-seed.txt",
				AccountConfigurationFile: "",
			},
			wantErr: true,
		},
		{
			name: "Validate with all valid files",
			fields: fields{
				CreateCredentials:        true,
				OperatorSeedFile:         "../../../test/aas/operator-seed.txt",
				AccountSeedFile:          "../../../test/aas/account-seed.txt",
				AccountConfigurationFile: "../../../test/aas/server.conf",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cc := &CreateCredentials{
				CreateCredentials:        tt.fields.CreateCredentials,
				NatsConfig:               tt.fields.NatsConfig,
				ConsoleWriter:            tt.fields.ConsoleWriter,
				OperatorSeedFile:         tt.fields.OperatorSeedFile,
				AccountSeedFile:          tt.fields.AccountSeedFile,
				AccountConfigurationFile: tt.fields.AccountConfigurationFile,
			}
			if err := cc.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateCredentials.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
