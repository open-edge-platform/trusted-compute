/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

func TestCreateDefaultFlavor_Run(t *testing.T) {
	type fields struct {
		DBConfig         commConfig.DBConfig
		commandName      string
		flvGroupStorePtr domain.FlavorGroupStore
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid flavor group store",
			fields: fields{
				DBConfig:         commConfig.DBConfig{},
				commandName:      "test",
				flvGroupStorePtr: mocks.NewFakeFlavorgroupStore(),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &CreateDefaultFlavor{
				DBConfig:         tt.fields.DBConfig,
				commandName:      tt.fields.commandName,
				flvGroupStorePtr: tt.fields.flvGroupStorePtr,
			}
			if err := tr.Run(); (err != nil) != tt.wantErr {
				t.Errorf("CreateDefaultFlavor.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			fmt.Println(tt.fields.flvGroupStorePtr)
			if err := tr.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateDefaultFlavor.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateDefaultFlavor_SetName(t *testing.T) {
	type fields struct {
		DBConfig         commConfig.DBConfig
		commandName      string
		flvGroupStorePtr domain.FlavorGroupStore
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &CreateDefaultFlavor{
				DBConfig:         tt.fields.DBConfig,
				commandName:      tt.fields.commandName,
				flvGroupStorePtr: tt.fields.flvGroupStorePtr,
			}
			tr.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestCreateDefaultFlavor_PrintHelp(t *testing.T) {
	type fields struct {
		DBConfig         commConfig.DBConfig
		commandName      string
		flvGroupStorePtr domain.FlavorGroupStore
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
			tr := &CreateDefaultFlavor{
				DBConfig:         tt.fields.DBConfig,
				commandName:      tt.fields.commandName,
				flvGroupStorePtr: tt.fields.flvGroupStorePtr,
			}
			w := &bytes.Buffer{}
			tr.PrintHelp(w)
			gotW := w.String()
			h := sha1.New()
			h.Write([]byte(gotW))
			bs := h.Sum(nil)
			if hex.EncodeToString(bs) != tt.wantW {
				t.Errorf("CreateDefaultFlavor.PrintHelp() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
