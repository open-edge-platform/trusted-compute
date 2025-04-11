/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"io"
	"os"
	"testing"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

func TestDatabase_Run(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		DBConfigPtr   *commConfig.DBConfig
		SSLCertSource string
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
			name: "Validate RUN with no sslcerts",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Vendor:   "test",
					Host:     "localhost",
					Port:     1234,
					DBName:   "test_db",
					Username: "testUser",
					Password: "testpassword",
				},
				DBConfig: commConfig.DBConfig{
					Host:     "localhost",
					Username: "test",
					Password: "password",
					DBName:   "test_db",
				},
				ConsoleWriter: os.Stdout,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &Database{
				DBConfig:      tt.fields.DBConfig,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				SSLCertSource: tt.fields.SSLCertSource,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := db.Run(); (err != nil) != tt.wantErr {
				t.Errorf("Database.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDatabase_Validate(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		DBConfigPtr   *commConfig.DBConfig
		SSLCertSource string
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
			name: "Validate with empty Hostname",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate with invalid Port",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host: "localhost",
					Port: 0,
				},
			},
			wantErr: true,
		},
		{
			name: "Validate with empty Username",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host:     "localhost",
					Port:     1234,
					Username: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate with empty Password",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host:     "localhost",
					Port:     1234,
					Username: "test",
					Password: "",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate with empty DBName",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host:     "localhost",
					Port:     1234,
					Username: "test",
					Password: "testPassword",
					DBName:   "",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate with empty SSLCert location",
			fields: fields{
				DBConfigPtr: &commConfig.DBConfig{
					Host:     "localhost",
					Port:     1234,
					Username: "test",
					Password: "testPassword",
					DBName:   "test_db",
					SSLMode:  "verify-full",
					SSLCert:  "",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &Database{
				DBConfig:      tt.fields.DBConfig,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				SSLCertSource: tt.fields.SSLCertSource,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := db.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Database.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDatabase_PrintHelp(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		DBConfigPtr   *commConfig.DBConfig
		SSLCertSource string
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "valid case",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &Database{
				DBConfig:      tt.fields.DBConfig,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				SSLCertSource: tt.fields.SSLCertSource,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			db.PrintHelp(w)
		})
	}
}

func TestDatabase_SetName(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		DBConfigPtr   *commConfig.DBConfig
		SSLCertSource string
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
			name: "valid case",
			args: args{
				n: "test",
				e: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &Database{
				DBConfig:      tt.fields.DBConfig,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				SSLCertSource: tt.fields.SSLCertSource,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			db.SetName(tt.args.n, tt.args.e)
		})
	}
}
