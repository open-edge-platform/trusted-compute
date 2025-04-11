/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDefineTagIndexPrintHelp(t *testing.T) {
	type fields struct {
		TpmF           tpmprovider.TpmFactory
		OwnerSecretKey string
		Config         *config.TrustAgentConfiguration
		envPrefix      string
		commandName    string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print help for define tag index",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DefineTagIndex{
				TpmF:           tt.fields.TpmF,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				Config:         tt.fields.Config,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()

		})
	}
}

func TestDefineTagIndexSetName(t *testing.T) {
	type fields struct {
		TpmF           tpmprovider.TpmFactory
		OwnerSecretKey string
		Config         *config.TrustAgentConfiguration
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
			name:   "Setname for DefineTagIndex",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &DefineTagIndex{
				TpmF:           tt.fields.TpmF,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				Config:         tt.fields.Config,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func runDefineTagIndex(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret string) error {

	defineTagIndexTask := DefineTagIndex{
		TpmF:           mockedTpmFactory,
		OwnerSecretKey: ownerSecret,
		Config:         &config.TrustAgentConfiguration{},
	}

	err := defineTagIndexTask.Run()
	if err != nil {
		return err
	}

	return defineTagIndexTask.Validate()
}

var quoteBytes = []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")

func TestDefineTagIndex(t *testing.T) {
	assert := assert.New(t)

	var index uint32
	var indexSize uint16
	index = 29425936
	indexSize = 48

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", tpmSecretKey).Return(true, nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider.On("NvDefine", tpmSecretKey, mock.Anything, index, indexSize).Return(nil)
	mockedTpmProvider.On("NvRelease", tpmSecretKey, mock.Anything).Return(nil)
	mockedTpmProvider.On("NvWrite", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	assert.Nil(runDefineTagIndex(t, mockedTpmFactory, tpmSecretKey))
}
