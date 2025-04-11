/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	"github.com/stretchr/testify/assert"
)

func TestProvisionAttestationIdentityKeyPrintHelp(t *testing.T) {
	type fields struct {
		TpmF                 tpmprovider.TpmFactory
		tpmp                 tpmprovider.TpmProvider
		ClientFactory        hvsclient.HVSClientFactory
		OwnerSecretKey       string
		EndorsementSecretKey string
		envPrefix            string
		commandName          string
		PrivacyCA            string
	}
	tests := []struct {
		name   string
		fields fields
		wantW  string
	}{
		{
			name:   "Print help for ProvisionAttestationIdentityKey",
			fields: fields{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ProvisionAttestationIdentityKey{
				TpmF:                 tt.fields.TpmF,
				tpmp:                 tt.fields.tpmp,
				ClientFactory:        tt.fields.ClientFactory,
				OwnerSecretKey:       tt.fields.OwnerSecretKey,
				EndorsementSecretKey: tt.fields.EndorsementSecretKey,
				envPrefix:            tt.fields.envPrefix,
				commandName:          tt.fields.commandName,
				PrivacyCA:            tt.fields.PrivacyCA,
			}
			w := &bytes.Buffer{}
			task.PrintHelp(w)
			_ = w.String()
		})
	}
}

func TestProvisionAttestationIdentityKeySetName(t *testing.T) {
	type fields struct {
		TpmF           tpmprovider.TpmFactory
		tpmp           tpmprovider.TpmProvider
		ClientFactory  hvsclient.HVSClientFactory
		OwnerSecretKey string
		envPrefix      string
		commandName    string
		PrivacyCA      string
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
			name:   "Setname for ProvisionAttestationIdentityKey",
			fields: fields{},
			args: args{
				n: "n",
				e: "e",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ProvisionAttestationIdentityKey{
				TpmF:           tt.fields.TpmF,
				tpmp:           tt.fields.tpmp,
				ClientFactory:  tt.fields.ClientFactory,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
				PrivacyCA:      tt.fields.PrivacyCA,
			}
			task.SetName(tt.args.n, tt.args.e)
		})
	}
}

func runProvisionAttestationIdentityKey(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret, endorsementSecret string, clientFactory hvsclient.MockedVSClientFactory) error {
	provisionAttestationIdentityKeyTask := ProvisionAttestationIdentityKey{
		TpmF:                 mockedTpmFactory,
		OwnerSecretKey:       ownerSecret,
		EndorsementSecretKey: endorsementSecret,
		ClientFactory:        clientFactory,
		PrivacyCA:            "../test/resources/privacy-ca.cer",
	}

	err := provisionAttestationIdentityKeyTask.Run()
	if err != nil {
		return err
	}

	return provisionAttestationIdentityKeyTask.Validate()
}

func TestProvisionAttestationIdentityKey(t *testing.T) {
	assert := assert.New(t)

	mockedPrivacyCaClient := new(hvsclient.MockedPrivacyCAClient)
	mockPrivacyCaClient(t, mockedPrivacyCaClient)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedPrivacyCAClient: mockedPrivacyCaClient}

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockTpmProvider(mockedTpmProvider)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	assert.Error(runProvisionAttestationIdentityKey(t, mockedTpmFactory, tpmSecretKey, endorsementSecretKey, mockedVSClientFactory))
}

func TestProvisionAttestationIdentityKeyValidate(t *testing.T) {
	type fields struct {
		TpmF           tpmprovider.TpmFactory
		tpmp           tpmprovider.TpmProvider
		ClientFactory  hvsclient.HVSClientFactory
		OwnerSecretKey string
		envPrefix      string
		commandName    string
		PrivacyCA      string
		AikCert        string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "Invalid ProvisionAttestationIdentityKey",
			fields:  fields{AikCert: ""},
			wantErr: true,
		},
		{
			name:    "Valid ProvisionAttestationIdentityKey",
			fields:  fields{AikCert: "../test/mockCACertsDir/681de0eca.pem"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &ProvisionAttestationIdentityKey{
				TpmF:           tt.fields.TpmF,
				tpmp:           tt.fields.tpmp,
				ClientFactory:  tt.fields.ClientFactory,
				OwnerSecretKey: tt.fields.OwnerSecretKey,
				envPrefix:      tt.fields.envPrefix,
				commandName:    tt.fields.commandName,
				PrivacyCA:      tt.fields.PrivacyCA,
				AikCert:        tt.fields.AikCert,
			}
			if err := task.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("ProvisionAttestationIdentityKey.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
