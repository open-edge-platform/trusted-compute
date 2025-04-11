/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
)

func TestProvisionPrimaryKeyPrintHelp(t *testing.T) {

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	type fields struct {
		TpmF           tpmprovider.TpmFactory
		OwnerSecretKey string
		envPrefix      string
		commandName    string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name: "Print help for ProvisionPrimaryKey",
			fields: fields{
				TpmF:           mockedTpmFactory,
				envPrefix:      ".isecl",
				commandName:    "c",
				OwnerSecretKey: tpmSecretKey,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ProvisionPrimaryKey{
				TpmF:           tt.fields.TpmF,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestProvisionPrimaryKeySetName(t *testing.T) {

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	type fields struct {
		TpmF           tpmprovider.TpmFactory
		OwnerSecretKey string
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
			name: "Set name for ProvisionPrimaryKey",
			fields: fields{
				TpmF:           mockedTpmFactory,
				envPrefix:      ".isecl",
				commandName:    "c",
				OwnerSecretKey: tpmSecretKey,
			},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ProvisionPrimaryKey{
				TpmF:           tt.fields.TpmF,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}
