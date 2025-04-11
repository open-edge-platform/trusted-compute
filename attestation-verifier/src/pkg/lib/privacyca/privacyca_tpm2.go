/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package privacyca

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/tpm2utils"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

// PrivacyCATpm2 will be having ProcessIdentityRequest method for Baremetal with tpm version 2.0
type PrivacyCATpm2 struct {
}

/**
 * Process an IdentityRequest Object returned from a TPM.
 * This function will encrypt an blob of data using the public portion of a key found inside the IdentityRequest object.
 * If a TPM can decrypt the blob of data, that serves as a proof of ownership over the private portion of that key.
 *
 * param request object from IdentityRequest
 * param pubEk public portion of the Tpm Endorsement Certificate
 * param identityChallenge arbitrary data the PrivacyCA wishes to encrypt. Can be a random challenge or an AIKCert, etc.
 * return IdentityProofRequest.
 */
func (privacycatpm2 *PrivacyCATpm2) ProcessIdentityRequest(request model.IdentityRequest, pubEk crypto.PublicKey, identityChallenge []byte) (model.IdentityProofRequest, error) {
	log.Trace("privacyca/privacyca_tpm2:ProcessIdentityRequest() Entering")
	defer log.Trace("privacyca/privacyca_tpm2:ProcessIdentityRequest() Leaving")

	key, err := crypt.GetRandomBytes(16)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca/privacyca_tpm2:ProcessIdentityRequest() Unable to generate Random Bytes for key")
	}

	iv, err := crypt.GetRandomBytes(16)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca/privacyca_tpm2:ProcessIdentityRequest() Unable to generate Random Bytes for iv")
	}

	encryptedIdentityChallenge, err := tpm2utils.EncryptSym(identityChallenge, key, iv, "CBC", "AES")
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca/privacyca_tpm2:ProcessIdentityRequest() Error while performing EncryptSym")
	}
	encryptedIdentityChallengeBlob := new(bytes.Buffer)
	err = binary.Write(encryptedIdentityChallengeBlob, binary.BigEndian, encryptedIdentityChallenge)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Wrap(err, "privacyca/privacyca_tpm2:ProcessIdentityRequest() Error writing identity challenge")
	}
	credential, err := tpm2utils.MakeCredential(pubEk, consts.TPM2AlgorithmSymmetricAES, consts.SymmetricKeyBits128, crypto.SHA256, key, request.AikName)
	if err != nil {
		return model.IdentityProofRequest{}, errors.Errorf("privacyca/privacyca_tpm2:ProcessIdentityRequest() Error while performing MakeCredential %+v", err)
	}

	symmetricKeyParams := model.TpmSymmetricKeyParams{
		TpmAlgId:              consts.TPM_ALG_AES,
		TpmAlgEncScheme:       consts.TPM_ES_NONE,
		TpmAlgSignatureScheme: 0,
		IV:                    iv,
	}

	identityProofRequest := model.IdentityProofRequest{
		Secret:                credential.Secret,
		Credential:            credential.CredentialBlob,
		TpmSymmetricKeyParams: symmetricKeyParams,
		SymmetricBlob:         encryptedIdentityChallengeBlob.Bytes(),
	}

	return identityProofRequest, nil
}

/**
 * Returns the decrypted ekcert bytes.
 * This function will decrypt a blob of data using privacyca private key and returns decrypted symmetric key.
 * The blob having ekcert bytes is decrypted using the decrypted symmetric key
 * param identityChallengePayload object from IdentityChallengePayload
 * param privacycaKey privacyca Private key
 * return Byte array having decryped endorsement Certificate in bytes.
 */
func (privacycatpm2 *PrivacyCATpm2) GetEkCert(identityChallengePayload model.IdentityChallengePayload, privacycaKey crypto.PrivateKey) ([]byte, error) {
	log.Trace("privacyca/privacyca_tpm2:GetEkCert() Entering")
	defer log.Trace("privacyca/privacyca_tpm2:GetEkCert() Leaving")

	symKey, err := tpm2utils.Tpm2DecryptAsym(identityChallengePayload.AsymBlob, privacycaKey, identityChallengePayload.TpmAsymmetricKeyParams.TpmAlgEncScheme, nil)
	if err != nil {
		return nil, errors.Wrap(err, "privacyca/privacyca_tpm2:GetEkCert() Error while decryption of asymmetric blob")
	}
	var ekCertBytes []byte
	if identityChallengePayload.TpmSymmetricKeyParams.TpmAlgEncScheme == consts.TPM_ES_SYM_CBC_PKCS5PAD {
		ekCertBytes, err = tpm2utils.DecryptSym(identityChallengePayload.SymBlob, symKey, identityChallengePayload.TpmSymmetricKeyParams.IV, "CBC", identityChallengePayload.TpmSymmetricKeyParams.TpmAlgId)
		if err != nil {
			return nil, errors.Wrap(err, "privacyca/privacyca_tpm2:GetEkCert() Error while decryption of symmetric blob")
		}
	}
	return ekCertBytes, nil
}

/**
 * Returns the encrypted endorsement cert bytes.
 * This function will encrypt a blob of data using randomly generated key using CBC AES Encryption scheme.
 * The symmetric key is encrypted with RSA SHA256 algorithm using public portion of Privacyca Cert
 * param payload data to be encrypted
 * param pubKey public portion of privacyca certificate
 * param identity Request.
 * return IdentityChallengePayload
 */
func (privacycatpm2 *PrivacyCATpm2) GetIdentityChallengeRequest(payload []byte, pubKey *rsa.PublicKey, request model.IdentityRequest) (model.IdentityChallengePayload, error) {
	log.Trace("privacyca/privacyca_tpm2:GetIdentityChallengeRequest() Entering")
	defer log.Trace("privacyca/privacyca_tpm2:GetIdentityChallengeRequest() Leaving")
	//---------------------------------------------------------------------------------------------
	// Encrypt the bytes using aes from https://golang.org/pkg/crypto/cipher/#example_NewCBCEncrypter
	//---------------------------------------------------------------------------------------------

	cipherKey, err := crypt.GetRandomBytes(16)
	if err != nil {
		return model.IdentityChallengePayload{}, errors.Wrap(err, "privacyca/privacyca_tpm2:GetIdentityChallengeRequest() Error while generating random bytes for cipher")
	}

	iv, err := crypt.GetRandomBytes(16) // aes.Blocksize == 16
	if err != nil {
		return model.IdentityChallengePayload{}, errors.Wrap(err, "privacyca/privacyca_tpm2:GetIdentityChallengeRequest() Error while generating random bytes for IV")
	}

	symmetricBytes, err := tpm2utils.EncryptSym(payload, cipherKey, iv, "CBC", "AES")
	if err != nil {
		return model.IdentityChallengePayload{}, err
	}

	tpmSymmetricKeyParams := model.TpmSymmetricKeyParams{
		TpmAlgId:              consts.TPM_ALG_AES,
		TpmAlgEncScheme:       consts.TPM_ES_SYM_CBC_PKCS5PAD,
		TpmAlgSignatureScheme: consts.TPM_SS_NONE,
		KeyLength:             128,
		BlockSize:             128,
		IV:                    iv,
	}

	asymKey, err := crypt.GetRandomBytes(32)
	if err != nil {
		return model.IdentityChallengePayload{}, err
	}

	// Encrypt the symmetric key using rsa sha256 Algorithm
	asymmetricBytes, err := rsa.EncryptOAEP(sha256.New(), bytes.NewBuffer(asymKey), pubKey, cipherKey, nil)
	if err != nil {
		return model.IdentityChallengePayload{}, errors.Wrap(err, "privacyca/privacyca_tpm2:GetIdentityChallengeRequest() Error while encrypting symmetric key")
	}

	asymmetricKeyParams := model.TpmAsymmetricKeyParams{
		TpmAlgId:              consts.TPM_ALG_RSA,
		TpmAlgEncScheme:       consts.TPM_ALG_ID_SHA256,
		TpmAlgSignatureScheme: consts.TPM_SS_NONE,
		KeyLength:             2048,
		PrimesCount:           2,
		ExponentSize:          0,
	}

	identityChallengePayload := model.IdentityChallengePayload{
		TpmAsymmetricKeyParams: asymmetricKeyParams,
		TpmSymmetricKeyParams:  tpmSymmetricKeyParams,
		SymBlob:                symmetricBytes,
		AsymBlob:               asymmetricBytes,
		IdentityRequest:        request,
	}
	return identityChallengePayload, nil
}
