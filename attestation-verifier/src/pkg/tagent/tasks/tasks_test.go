/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	tpmSecretKey         = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	endorsementSecretKey = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	bearerToken          = "abcdefghijklmnoqrstuvwxyz"
)

//
// These tests can be run (in tpm-devel container) via...
//   env CGO_CFLAGS_ALLOW="-f.*" go test -v -tags unit_test -run TestTakeOwnership* intel/isecl/go-trust-agent/v5/tasks
//

func runTakeOwnership(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret, endorsementSecret string) error {

	takeOwnership := TakeOwnership{TpmF: mockedTpmFactory, OwnerSecretKey: ownerSecret, EndorsementSecretKey: endorsementSecret}

	err := takeOwnership.Run()
	if err != nil {
		return err
	}

	return nil
}

func runTakeOwnershipValidate(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret, endorsementSecret string) error {

	takeOwnership := TakeOwnership{TpmF: mockedTpmFactory, OwnerSecretKey: ownerSecret, EndorsementSecretKey: endorsementSecret}

	err := takeOwnership.Validate()
	if err != nil {
		return err
	}

	return nil
}

func runProvisionPrimaryKey(t *testing.T, mockedTpmFactory tpmprovider.MockedTpmFactory, ownerSecret string) error {
	provisionPrimaryKeyTask := ProvisionPrimaryKey{
		TpmF:           mockedTpmFactory,
		OwnerSecretKey: ownerSecret,
	}

	err := provisionPrimaryKeyTask.Run()
	if err != nil {
		return err
	}

	return provisionPrimaryKeyTask.Validate()
}

// If the empty password is provided (TPM_OWNER_SECRET="") and
// the TPM is in a clear state, expect take-ownership to be successful.
func TestTakeOwnershipEmptySecretClearTPM(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	err := runTakeOwnership(t, mockedTpmFactory, "", "")
	if err != nil {
		t.Fatal(err) // unexpected
	}
}

func TestTakeOwnershipValidate(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything, mock.Anything).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	err := runTakeOwnershipValidate(t, mockedTpmFactory, "", "")
	if err != nil {
		t.Fatal(err) // unexpected
	}
}

// If the empty password is provided (TPM_OWNER_SECRET="") and
// the TPM has a different owner-secret expect take-ownership to fail.
func TestTakeOwnershipEmptySecretNotClearTPM(t *testing.T) {

	// mock a "not cleared" TPM (i.e., that fails when "" is used for
	// the owner-secret).
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", mock.Anything, mock.Anything).Return(errors.New(""))
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(false, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	err := runTakeOwnership(t, mockedTpmFactory, "", "")
	if err == nil {
		t.Fatalf("The unit test expected take-ownership to fail")
	}

	t.Log(err)
}

// If the owner-secret is provided (TPM_OWNER_SECRET="xyz") and
// the TPM is clear, expect the task to take-ownership of the TPM
// using the owner-secret.
func TestTakeOwnershipProvidedSecretClearTPM(t *testing.T) {

	// mock "clear" TPM
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", tpmSecretKey, endorsementSecretKey).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", tpmSecretKey).Return(false, nil)
	mockedTpmProvider.On("IsOwnedWithAuth", "").Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	err := runTakeOwnership(t, mockedTpmFactory, tpmSecretKey, endorsementSecretKey)
	if err != nil {
		t.Fatal(err) // unexpected
	}
}

// If the owner-secret is provided (TPM_OWNER_SECRET="xyz") and
// the TPM is owned with that password, expect take-ownership to be
// successful.
func TestTakeOwnershipProvidedSecretThatOwnsTPM(t *testing.T) {

	// TPM that is owned by 'tpmSecretKey'
	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("Version", mock.Anything).Return(tpmprovider.V20)
	mockedTpmProvider.On("TakeOwnership", tpmSecretKey, endorsementSecretKey).Return(nil)
	mockedTpmProvider.On("IsOwnedWithAuth", tpmSecretKey).Return(true, nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	err := runTakeOwnership(t, mockedTpmFactory, tpmSecretKey, endorsementSecretKey)
	if err != nil {
		t.Fatal(err) // unexpected
	}
}

func TestCreateHostDefault(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.Server.Port = 8045
	cfg.Mode = constants.CommunicationModeHttp

	// create mocks that return no hosts on 'SearchHosts' (i.e. host does not exist in hvs) and
	// host with an new id for 'CreateHost'
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	os.Setenv(constants.EnvBearerToken, bearerToken)
	createHost := CreateHost{AppConfig: cfg, ClientFactory: mockedVSClientFactory, TrustAgentPort: cfg.Server.Port}
	err := createHost.Run()
	assert.NoError(err)
}

func TestCreateHostExisting(t *testing.T) {
	assert := assert.New(t)

	cfg := &config.TrustAgentConfiguration{}
	cfg.Server.Port = 8045
	cfg.Mode = constants.CommunicationModeHttp

	hwUuid := uuid.MustParse("8032632b-8fa4-e811-906e-00163566263e")
	existingHost := hvs.Host{
		Id:               uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723d"),
		HostName:         "ta.server.com",
		Description:      "GTA RHEL 8.0",
		ConnectionString: "https://ta.server.com:1443",
		HardwareUuid:     &hwUuid,
	}

	// create mocks that return a host (i.e. it exists in hvs)
	mockedHostsClient := new(hvsclient.MockedHostsClient)
	mockedHostsClient.On("SearchHosts", mock.Anything).Return(&hvs.HostCollection{Hosts: []*hvs.Host{&existingHost}}, nil)
	mockedHostsClient.On("CreateHost", mock.Anything).Return(&hvs.Host{Id: uuid.MustParse("068b5e88-1886-4ac2-a908-175cf723723f")}, nil)

	os.Setenv(constants.EnvCurrentIP, "99.99.99.99")
	os.Setenv(constants.EnvBearerToken, bearerToken)
	mockedVSClientFactory := hvsclient.MockedVSClientFactory{MockedHostsClient: mockedHostsClient}

	createHost := CreateHost{AppConfig: cfg, ClientFactory: mockedVSClientFactory, TrustAgentPort: cfg.Server.Port}
	err := createHost.Run()
	assert.Error(err)
}

func TestProvisionPrimaryKeySuccess(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("PublicKeyExists", mock.Anything).Return(true, nil)
	mockedTpmProvider.On("CreatePrimaryHandle", mock.Anything, mock.Anything).Return(nil)
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	assert.Nil(runProvisionPrimaryKey(t, mockedTpmFactory, tpmSecretKey))
}

func TestProvisionPrimaryKeyFail(t *testing.T) {
	assert := assert.New(t)

	mockedTpmProvider := new(tpmprovider.MockedTpmProvider)
	mockedTpmProvider.On("Close").Return(nil)
	mockedTpmProvider.On("PublicKeyExists", mock.Anything).Return(false, errors.New("Public key does not exist"))
	mockedTpmProvider.On("CreatePrimaryHandle", mock.Anything, mock.Anything).Return(errors.Errorf("CreatePrimaryHandle returned error code 0x%x", 0x22))
	mockedTpmFactory := tpmprovider.MockedTpmFactory{TpmProvider: mockedTpmProvider}

	assert.Error(runProvisionPrimaryKey(t, mockedTpmFactory, tpmSecretKey))
}
