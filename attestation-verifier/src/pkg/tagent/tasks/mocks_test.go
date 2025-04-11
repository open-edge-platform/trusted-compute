/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func mockTpmProvider(mockedTpmProvider *tpmprovider.MockedTpmProvider) {
	tpmSecretKey := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	endorsementSecretKey := "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	var quoteBytes = []byte("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	var keyBytes = []byte("1234567890123456")

	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("NvIndexExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("CreateEk", tpmSecretKey, endorsementSecretKey, mock.Anything).Return(nil)
	mockedTpmProvider.On("CreateAik", tpmSecretKey, endorsementSecretKey).Return(nil)
	mockedTpmProvider.On("IsValidEk", tpmSecretKey, mock.Anything, mock.Anything).Return(true, nil)
	mockedTpmProvider.On("NvRead", tpmSecretKey, mock.Anything, mock.Anything).Return(quoteBytes, nil)
	mockedTpmProvider.On("GetAikBytes").Return(quoteBytes, nil)
	mockedTpmProvider.On("GetAikName").Return([]byte("TestAikName"), nil)
	mockedTpmProvider.On("ActivateCredential", endorsementSecretKey, mock.Anything, mock.Anything).Return(keyBytes, nil)

}

func mockPrivacyCaClient(t *testing.T, mockedPrivacyCaClient *hvsclient.MockedPrivacyCAClient) {

	var shortBytes = 2
	var keyBytes = []byte("1234567890123456")

	credentialBlob := new(bytes.Buffer)
	err := binary.Write(credentialBlob, binary.BigEndian, int16(shortBytes))
	if err != nil {
		assert.NoError(t, err)
	}

	secretsBlob := new(bytes.Buffer)
	err = binary.Write(secretsBlob, binary.BigEndian, int16(shortBytes))
	if err != nil {
		assert.NoError(t, err)
	}

	mockedPrivacyCaClient.On("DownloadPrivacyCa", mock.Anything).Return([]uint8{}, nil)
	mockedPrivacyCaClient.On("GetIdentityProofRequest", mock.Anything).Return(&taModel.IdentityProofRequest{Credential: credentialBlob.Bytes(), Secret: secretsBlob.Bytes(), SymmetricBlob: keyBytes, TpmSymmetricKeyParams: taModel.TpmSymmetricKeyParams{IV: keyBytes}}, nil)
	mockedPrivacyCaClient.On("GetIdentityProofResponse", mock.Anything).Return(&taModel.IdentityProofRequest{Credential: credentialBlob.Bytes(), Secret: secretsBlob.Bytes(), SymmetricBlob: keyBytes, TpmSymmetricKeyParams: taModel.TpmSymmetricKeyParams{IV: keyBytes}}, nil)
}
