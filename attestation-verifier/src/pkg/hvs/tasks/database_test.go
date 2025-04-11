/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"testing"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	log "github.com/sirupsen/logrus"
)

func TestDBSetup_Run(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		SSLCertSource string
		DBConfigPtr   *commConfig.DBConfig
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	createCert()
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "DB error",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "DB ptr nil",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   nil,
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Invalid connection retry attempts",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:                  "test",
					Host:                    "test",
					Port:                    1223,
					DBName:                  "test",
					Username:                "test",
					Password:                "test",
					SSLMode:                 "test",
					SSLCert:                 "test.pem",
					ConnectionRetryAttempts: -1,
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Invalid connection retry time",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:              "test",
					Host:                "test",
					Port:                1223,
					DBName:              "test",
					Username:            "test",
					Password:            "test",
					SSLMode:             "test",
					SSLCert:             "test.pem",
					ConnectionRetryTime: -1,
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Vendor not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Host not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Port not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     0,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "DB name not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Username not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "Password not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "SSL mode not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "SSL cert not provided",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   &commConfig.DBConfig{},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DBSetup{
				DBConfig:      tt.fields.DBConfig,
				SSLCertSource: tt.fields.SSLCertSource,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := tr.Run(); (err != nil) != tt.wantErr {
				t.Errorf("DBSetup.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("test.pem")
}

func TestDBSetup_Validate(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		SSLCertSource string
		DBConfigPtr   *commConfig.DBConfig
		ConsoleWriter io.Writer
		envPrefix     string
		commandName   string
	}
	createCert()
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "DB error",
			fields: fields{
				SSLCertSource: "test.pem",
				DBConfigPtr: &commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test",
				},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "DB ptr nil",
			fields: fields{
				DBConfig: commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test.pem",
				},
				SSLCertSource: "test.pem",
				DBConfigPtr:   nil,
			},
			wantErr: true,
		},
		{
			name: "Empty host error",
			fields: fields{
				SSLCertSource: "test.pem",
				DBConfigPtr: &commConfig.DBConfig{
					Vendor:   "test",
					Host:     "",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "test",
					SSLCert:  "test",
				},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
		{
			name: "SSL cert not found",
			fields: fields{
				SSLCertSource: "test.pem",
				DBConfigPtr: &commConfig.DBConfig{
					Vendor:   "test",
					Host:     "test",
					Port:     1223,
					DBName:   "test",
					Username: "test",
					Password: "test",
					SSLMode:  "verify-ca",
					SSLCert:  "test",
				},
				ConsoleWriter: os.Stdout,
				envPrefix:     "test",
				commandName:   "test",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DBSetup{
				DBConfig:      tt.fields.DBConfig,
				SSLCertSource: tt.fields.SSLCertSource,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			if err := tr.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("DBSetup.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	os.Remove("test.pem")
}

func createCert() {
	derBytes, _, err := crypt.CreateKeyPairAndCertificate("test", "test", "rsa", 3072)
	if err != nil {
		log.Error("Error in creating key pair and certificate")
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	err = os.WriteFile("test.pem", cert, 0644)
	if err != nil {
		log.Error(err)
	}
}

func TestDBSetup_SetName(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		SSLCertSource string
		DBConfigPtr   *commConfig.DBConfig
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
			name: "Set command name",
			args: args{
				n: "test",
				e: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DBSetup{
				DBConfig:      tt.fields.DBConfig,
				SSLCertSource: tt.fields.SSLCertSource,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			tr.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestDBSetup_PrintHelp(t *testing.T) {
	type fields struct {
		DBConfig      commConfig.DBConfig
		SSLCertSource string
		DBConfigPtr   *commConfig.DBConfig
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
			name:  " Print help statement",
			wantW: "2da752f1ed186c41977f77afd19253439af18cdb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &DBSetup{
				DBConfig:      tt.fields.DBConfig,
				SSLCertSource: tt.fields.SSLCertSource,
				DBConfigPtr:   tt.fields.DBConfigPtr,
				ConsoleWriter: tt.fields.ConsoleWriter,
				envPrefix:     tt.fields.envPrefix,
				commandName:   tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			tr.PrintHelp(w)
			gotW := w.String()
			h := sha1.New()
			h.Write([]byte(gotW))
			bs := h.Sum(nil)
			if hex.EncodeToString(bs) != tt.wantW {
				t.Errorf("DBSetup.PrintHelp() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}

func Test_configureDBSSLParams(t *testing.T) {
	type args struct {
		sslMode    string
		sslCertSrc string
		sslCert    string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "ssl mode is verify-ca and sslcert is not found",
			args: args{
				sslMode: "verify-ca",
				sslCert: "test",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "ssl mode is verify-ca and sslcertSrc is empty",
			args: args{
				sslMode:    "verify-ca",
				sslCert:    "",
				sslCertSrc: "",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "ssl mode is verify-ca and sslcertSrc is not found",
			args: args{
				sslMode:    "verify-ca",
				sslCert:    "",
				sslCertSrc: "test",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
		{
			name: "ssl mode is verify-ca and sslcertSrc is found - copy error",
			args: args{
				sslMode:    "verify-ca",
				sslCert:    "",
				sslCertSrc: "../utils",
			},
			want:    "",
			want1:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := configureDBSSLParams(tt.args.sslMode, tt.args.sslCertSrc, tt.args.sslCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("configureDBSSLParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("configureDBSSLParams() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("configureDBSSLParams() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
