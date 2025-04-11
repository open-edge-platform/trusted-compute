/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	"github.com/pkg/errors"
)

func TestGetEndorsementKeyCertificateBytes(t *testing.T) {
	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)

	var NV_IDX, NV_IDX_X509_P384_EK_CERTCHAIN uint32
	NV_IDX = 0x1c00002
	NV_IDX_X509_P384_EK_CERTCHAIN = 0x1c00100

	var TPM2_RH_OWNER, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE uint32
	TPM2_RH_OWNER = 0x40000001
	NV_IDX_RSA_ENDORSEMENT_CERTIFICATE = 0x1c00002

	mockedTpmProvider.On("NvIndexExists", NV_IDX).Return(true, nil)
	mockedTpmProvider.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE).Return([]byte("test_bytes"), nil)
	mockedTpmProvider.On("NvIndexExists", NV_IDX_X509_P384_EK_CERTCHAIN).Return(true, nil)
	mockedTpmProvider.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_X509_P384_EK_CERTCHAIN).Return([]byte("test_bytes"), nil)

	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	// mockedTpmProvider for negative case
	mockedTpmProvider1 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider1.On("Close").Return(nil)
	mockedTpmProvider1.On("NvIndexExists", NV_IDX).Return(false, nil)
	mockedTpmFactory1 := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider1}

	// mockedTpmProvider2 for negative case
	mockedTpmProvider2 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider2.On("Close").Return(nil)
	mockedTpmProvider2.On("NvIndexExists", NV_IDX).Return(false, errors.New("Error checking if the EK Certificate is present"))
	mockedTpmFactory2 := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider2}

	// mockedTpmProvider3 for negative case
	mockedTpmProvider3 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider3.On("Close").Return(nil)
	mockedTpmProvider3.On("NvIndexExists", NV_IDX).Return(true, nil)
	mockedTpmProvider3.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE).Return([]byte(""), errors.New("Error while performing tpm NvRead operation"))
	mockedTpmFactory3 := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider3}

	// mockedTpmProvider4 for negative case
	mockedTpmProvider4 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider4.On("Close").Return(nil)
	mockedTpmProvider4.On("NvIndexExists", NV_IDX).Return(true, nil)
	mockedTpmProvider4.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE).Return([]byte("test_bytes"), nil)
	mockedTpmProvider4.On("NvIndexExists", NV_IDX_X509_P384_EK_CERTCHAIN).Return(false, errors.New("Error checking if the EK Issuing Cert Chain is present"))
	mockedTpmFactory4 := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider4}

	// mockedTpmProvider5 for negative case
	mockedTpmProvider5 := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider5.On("Close").Return(nil)
	mockedTpmProvider5.On("NvIndexExists", NV_IDX).Return(true, nil)
	mockedTpmProvider5.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE).Return([]byte("test_bytes"), nil)
	mockedTpmProvider5.On("NvIndexExists", NV_IDX_X509_P384_EK_CERTCHAIN).Return(true, nil)
	mockedTpmProvider5.On("NvRead", "", TPM2_RH_OWNER, NV_IDX_X509_P384_EK_CERTCHAIN).Return([]byte(""), errors.New("Error while performing tpm NvRead operation"))
	mockedTpmFactory5 := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider5}

	type args struct {
		ownerSecretKey string
		tpmFactory     tpmprovider.TpmFactory
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Valid case",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory,
			},
			wantErr: false,
		},
		{
			name: "Invalid case to validate NIL ekCertificateExists",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory1,
			},
			wantErr: true,
		},
		{
			name: "Invalid case to validate NvIndexExists",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory2,
			},
			wantErr: true,
		},
		{
			name: "Invalid case to validate NvRead",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory3,
			},
			wantErr: true,
		},
		{
			name: "Invalid case to validate NvIndexExists with NV_IDX_X509_P384_EK_CERTCHAIN",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory4,
			},
			wantErr: true,
		},
		{
			name: "Invalid case to validate NvRead NV_IDX_X509_P384_EK_CERTCHAIN",
			args: args{
				ownerSecretKey: "",
				tpmFactory:     mockedTpmFactory5,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetEndorsementKeyCertificateBytes(tt.args.ownerSecretKey, tt.args.tpmFactory)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEndorsementKeyCertificateBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
