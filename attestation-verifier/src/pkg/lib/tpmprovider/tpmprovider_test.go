/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tpmprovider

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

//
// These unit tests can be run from the root of the project by running...
//
// env CGO_CFLAGS_ALLOW="-f.*" go test -tags=unit_test -v ./...
//

const (
	OwnerSecretKey       = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	endorsementSecretKey = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
	TagSecretKey         = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
	BadSecretKey         = "b000b000b000b000b000b000b000b000b000b000"
	HexSecretKey         = "hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	CertifiedKeySecret   = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
	SimpleSecretKey      = "mypassword"
)

// Provisiones a new instance of the TPM simulator with an owner secret or EK Certificate.
func newSimulatorAndProvider(t *testing.T) (TpmSimulator, TpmProvider) {

	tpmSimulator := NewTpmSimulator()
	err := tpmSimulator.Start()
	if err != nil {
		assert.FailNowf(t, "Could not start TPM Simulator", "%s", err)
	}

	tpmFactory, err := MsSimTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		tpmSimulator.Stop()
		assert.FailNowf(t, "Could create TPM Factory", "%s", err)
	}

	tpmProvider, err := tpmFactory.NewTpmProvider()
	if err != nil {
		tpmSimulator.Stop()
		assert.FailNowf(t, "Could not create TPM Provider", "%s", err)
	}

	return tpmSimulator, tpmProvider
}

func provisionSimulator(t *testing.T, tpmProvider TpmProvider, tpmSimulator TpmSimulator) {

	err := tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		tpmSimulator.Stop()
		assert.FailNowf(t, "Failed to take ownership", "%s", err)
	}

	// Creating an AIK requires an EK which requires an EK Certificate, provision one in the
	// tpm simulator...
	err = tpmSimulator.ProvisionEkCertificate(tpmProvider, OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		tpmSimulator.Stop()
		assert.FailNowf(t, "Could not provision the EK Certificate in the TPM Simulator", "%s", err)
	}

	return
}

func TestTpmFactory(t *testing.T) {

	tpmSimulator := NewTpmSimulator()
	err := tpmSimulator.Start()
	if err != nil {
		assert.FailNowf(t, "Could not start TPM Simulator", "%s", err)
	}

	defer tpmSimulator.Stop()

	tpmFactory, err := MsSimTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		assert.FailNowf(t, "Could create TPM Factory", "%s", err)
	}

	for i := 1; i < 5; i++ {
		tpmProvider, err := tpmFactory.NewTpmProvider()
		if err != nil {
			assert.FailNowf(t, "Could not create TPM Provider", "%s", err)
		}

		_, err = tpmProvider.IsOwnedWithAuth(OwnerSecretKey)
		if err != nil {
			assert.FailNowf(t, "", "%s", err)
		}

		tpmProvider.Close()
	}
}

func TestTpmVersion(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	version := tpmProvider.Version()
	assert.NotEqual(t, version, 0)
}

func TestTakeOwnershipWithValidSecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestTakeOwnershipWithEmptySecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership("", "")
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestTakeOwnershipWithSimpleSecretKey(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(SimpleSecretKey, SimpleSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestTakeOwnershipWithSimplePassword(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership("deadbeef", "beefbeef")
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestIsOwnedWithAuthPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	owned, err := tpmProvider.IsOwnedWithAuth(OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, owned)
}

func TestIsOwnedWithHexPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(HexSecretKey, HexSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	owned, err := tpmProvider.IsOwnedWithAuth(HexSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, owned)
}

func TestIsOwnedWithHexCompatibility(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(HexSecretKey, HexSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	owned, err := tpmProvider.IsOwnedWithAuth(OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, owned)
}

func TestSecretValidation(t *testing.T) {

	var keyBytes []byte
	var err error

	h, _ := hex.DecodeString(OwnerSecretKey)

	keyBytes, err = validateAndConvertKey(OwnerSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.Equal(t, keyBytes, h)

	keyBytes, err = validateAndConvertKey(HexSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.Equal(t, keyBytes, h)

	keyBytes, err = validateAndConvertKey(SimpleSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.Equal(t, keyBytes, []byte(SimpleSecretKey))

}

func TestIsOwnedWithAuthNegative(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	err := tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	owned, err := tpmProvider.IsOwnedWithAuth(BadSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.False(t, owned)
}

func TestCreateAikPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	isValidEk, err := tpmProvider.IsValidEk(OwnerSecretKey, TPM_HANDLE_EK, NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		assert.FailNowf(t, "Error validating EK", "%s", err)
	}

	if !isValidEk {
		assert.FailNowf(t, "The EK is not valid", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestGetAikBytesPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	output, err := tpmProvider.GetAikBytes()
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEqual(t, len(output), 0)
}

func TestGetAikNamePositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	output, err := tpmProvider.GetAikName()
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEqual(t, len(output), 0)
}

func TestActivateCredentialInvalidOwnerSecret(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	credentialBytes := make([]byte, 20)
	secretBytes := make([]byte, 20)

	// just testing the secret key at this time...
	_, err = tpmProvider.ActivateCredential(BadSecretKey, credentialBytes, secretBytes)
	assert.Error(t, err)
}

func TestTpmQuotePositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// Test quote
	nonce, _ := base64.StdEncoding.DecodeString("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=")
	pcrs := []int{0, 1, 2, 3, 18, 19, 22}
	pcrBanks := []string{"SHA1", "SHA256"}
	quoteBytes, err := tpmProvider.GetTpmQuote(nonce, pcrBanks, pcrs)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEqual(t, len(quoteBytes), 0)
}

// Similar to...
// tpm2_nvdefine -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -s 1024 -t 0x2000a # (ownerread|ownerwrite|policywrite)
// tpm2_nvwrite -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 /tmp/quote.bin
// tpm2_nvread -P hex:deadbeefdeadbeefdeadbeefdeadbeefdeadbeef -x 0x1c10110 -a 0x40000001 -o 0 -f /tmp/quote_nv.bin
func TestNvRamPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	// take ownership
	err := tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// define/read/write/delete some data in nvram
	idx := uint32(NV_IDX_ASSET_TAG)
	data := make([]byte, 256) // just test something over 1024 bytes which seems to be an issue with physical tpms

	err = tpmProvider.NvDefine(OwnerSecretKey, TagSecretKey, idx, uint16(len(data)))
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.NvWrite(TagSecretKey, idx, idx, data)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	output, err := tpmProvider.NvRead(TagSecretKey, idx, idx)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.Equal(t, data, output)

	err = tpmProvider.NvRelease(OwnerSecretKey, idx)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestCreatePrimaryHandlePositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	err := tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}
}

func TestSigningPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the primary key used for creating the singing key...
	err = tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	signingKey, err := tpmProvider.CreateSigningKey(CertifiedKeySecret)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEmpty(t, signingKey.PublicKey)
	assert.NotEmpty(t, signingKey.PrivateKey)
	assert.NotEmpty(t, signingKey.KeySignature)
	assert.NotEmpty(t, signingKey.KeyAttestation)
	assert.NotEmpty(t, signingKey.KeyName)
	assert.Equal(t, signingKey.Usage, Signing)
	assert.Equal(t, signingKey.Version, V20)

	// just hash some bytes (in this case the aik secret key) and make sure
	// no error occurs and bytes are returned
	hashToSign := make([]byte, 32, 32)
	signedBytes, err := tpmProvider.Sign(signingKey, CertifiedKeySecret, hashToSign)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEqual(t, len(signedBytes), 0)
}

func TestBindingPositive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	// create the EK and AIK
	err := tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the primary key used for creating the singing key...
	err = tpmProvider.CreatePrimaryHandle(OwnerSecretKey, TPM_HANDLE_PRIMARY)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	bindingKey, err := tpmProvider.CreateBindingKey(CertifiedKeySecret)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.NotEmpty(t, bindingKey.PublicKey)
	assert.NotEmpty(t, bindingKey.PrivateKey)
	assert.NotEmpty(t, bindingKey.KeySignature)
	assert.NotEmpty(t, bindingKey.KeyAttestation)
	assert.NotEmpty(t, bindingKey.KeyName)
	assert.Equal(t, bindingKey.Usage, Binding)
	assert.Equal(t, bindingKey.Version, V20)

	// just hash some bytes (in this case the aik secret key) and make sure
	// no error occurs and bytes are returned
	// tpmprovider.sign uses rsa/sha256, hash needs be 32 bytes long
	// encryptedBytes := make([]byte, 32, 32)
	// decryptedBytes, err := tpmProvider.Unbind(bindingKey, CertifiedKeySecret, encryptedBytes)
	// assert.NoError(t, err)
	// assert.NotEqual(t, len(decryptedBytes), 0)
}

func TestMultiThreadedQuote(t *testing.T) {

	// This unit test is being skipped since it because deadlock occurs when the TSS2 is
	// configured to use the mssim tcti directory.  The test will pass if
	// it is run against /dev/tpmrm0 via NewTpmFactory().
	t.Skip()

	var wg sync.WaitGroup

	tpmFactory, err := MsSimTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		assert.FailNowf(t, "Could not create TPM Factory", "%s", err)
	}

	// Provision the TPM to support quotes...
	tpmProvider, err := tpmFactory.NewTpmProvider()
	if err != nil {
		assert.FailNowf(t, "Could not create TPM Provider", "%s", err)
	}

	err = tpmProvider.TakeOwnership(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// create the EK and AIK
	err = tpmProvider.CreateEk(OwnerSecretKey, endorsementSecretKey, TPM_HANDLE_EK)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	err = tpmProvider.CreateAik(OwnerSecretKey, endorsementSecretKey)
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	// close the tpmprovider that did provisioning (this isn't multithreaded in the real world)
	tpmProvider.Close()

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(threadNum int) {
			defer wg.Done()

			// generate some sleep somewhere under a second
			sleep, err := rand.Int(rand.Reader, big.NewInt(1000))
			if err != nil {
				assert.FailNowf(t, "", "%s", err)
			}

			fmt.Printf("Thread[%d]: Sleeping for %d milliseconds\n", threadNum, sleep)
			time.Sleep(time.Duration(sleep.Int64()))

			tpm, err := tpmFactory.NewTpmProvider()
			if err != nil {
				assert.FailNowf(t, "", "%s", err)
			}

			defer tpm.Close()

			nonce, _ := base64.StdEncoding.DecodeString("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZiA=")
			pcrs := []int{0, 1, 2, 3, 18, 19, 22}
			pcrBanks := []string{"SHA1", "SHA256"}

			fmt.Printf("Thread[%d][%s]: Starting tpm quote\n", threadNum, time.Now().String())
			quoteBytes, err := tpm.GetTpmQuote(nonce, pcrBanks, pcrs)
			if err != nil {
				assert.FailNowf(t, "", "%s", err)
			}

			assert.NotEqual(t, len(quoteBytes), 0)
			fmt.Printf("Thread[%d][%s]: Successfully completed tpm quote\n", threadNum, time.Now().String())
		}(i)
	}

	wg.Wait()
}

func TestDetectPcrActive(t *testing.T) {

	tpmSimulator, tpmProvider := newSimulatorAndProvider(t)
	defer tpmSimulator.Stop()
	defer tpmProvider.Close()

	provisionSimulator(t, tpmProvider, tpmSimulator)

	isActivePcr, err := tpmProvider.IsPcrBankActive("SHA1")
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, isActivePcr)

	isActivePcr, err = tpmProvider.IsPcrBankActive("SHA256")
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, isActivePcr)

	isActivePcr, err = tpmProvider.IsPcrBankActive("SHA384")
	if err != nil {
		assert.FailNowf(t, "", "%s", err)
	}

	assert.True(t, isActivePcr)

	isActivePcr, err = tpmProvider.IsPcrBankActive("ABCD")
	assert.Error(t, err)
	assert.False(t, isActivePcr)
}
