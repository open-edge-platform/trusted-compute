/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

func TestCreateDefaultFlavorTemplate_Run(t *testing.T) {
	type fields struct {
		DBConf        commConfig.DBConfig
		commandName   string
		TemplateStore domain.FlavorTemplateStore
		FGStore       domain.FlavorGroupStore
		Directory     string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Valid case - Create default flavor template",
			fields: fields{
				DBConf:        commConfig.DBConfig{},
				commandName:   "test",
				TemplateStore: mocks.NewFakeFlavorTemplateStore(),
				FGStore:       mocks.NewFakeFlavorgroupStore(),
				Directory:     "../../../build/linux/hvs/templates/",
			},
			wantErr: false,
		},
		{
			name: "Template store is not present",
			fields: fields{
				DBConf:        commConfig.DBConfig{},
				commandName:   "test",
				TemplateStore: nil,
				FGStore:       mocks.NewFakeFlavorgroupStore(),
				Directory:     "../../../build/linux/hvs/templates/",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &CreateDefaultFlavorTemplate{
				DBConf:        tt.fields.DBConf,
				commandName:   tt.fields.commandName,
				TemplateStore: tt.fields.TemplateStore,
				FGStore:       tt.fields.FGStore,
				Directory:     tt.fields.Directory,
			}
			if err := tr.Run(); (err != nil) != tt.wantErr {
				t.Errorf("CreateDefaultFlavorTemplate.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := tr.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("CreateDefaultFlavorTemplate.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateDefaultFlavorTemplate_SetName(t *testing.T) {
	type fields struct {
		DBConf        commConfig.DBConfig
		commandName   string
		TemplateStore domain.FlavorTemplateStore
		FGStore       domain.FlavorGroupStore
		Directory     string
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
			tr := &CreateDefaultFlavorTemplate{
				DBConf:        tt.fields.DBConf,
				commandName:   tt.fields.commandName,
				TemplateStore: tt.fields.TemplateStore,
				FGStore:       tt.fields.FGStore,
				Directory:     tt.fields.Directory,
			}
			tr.SetName(tt.args.n, tt.args.e)
		})
	}
}

func TestCreateDefaultFlavorTemplate_PrintHelp(t *testing.T) {
	type fields struct {
		DBConf        commConfig.DBConfig
		commandName   string
		TemplateStore domain.FlavorTemplateStore
		FGStore       domain.FlavorGroupStore
		Directory     string
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
			tr := &CreateDefaultFlavorTemplate{
				DBConf:        tt.fields.DBConf,
				commandName:   tt.fields.commandName,
				TemplateStore: tt.fields.TemplateStore,
				FGStore:       tt.fields.FGStore,
				Directory:     tt.fields.Directory,
			}
			w := &bytes.Buffer{}
			tr.PrintHelp(w)
			gotW := w.String()
			h := sha1.New()
			h.Write([]byte(gotW))
			bs := h.Sum(nil)
			if hex.EncodeToString(bs) != tt.wantW {
				t.Errorf("CreateDefaultFlavorTemplate.PrintHelp() = %v, want %v", gotW, tt.wantW)
			}
		})
	}
}
