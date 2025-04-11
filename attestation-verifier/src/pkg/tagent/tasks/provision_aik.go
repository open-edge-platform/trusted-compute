/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
)

const provisionAttestationIdentityKeyEnvHelpPrompt = "Following environment variables are required for " +
	constants.ProvisionAttestationIdentityKeyCommand + " setup:"

var provisionAttestationIdentityKeyEnvHelp = map[string]string{
	constants.EnvVSAPIURL:             "VS API URL",
	constants.EnvBearerToken:          "JWT token for authenticating with VS",
	constants.EnvTPMOwnerSecret:       "TPM Owner Secret",
	constants.EnvTPMEndorsementSecret: "TPM Endorsement Secret",
}

const CertificatePemBlockHeader = "CERTIFICATE"

//-------------------------------------------------------------------------------------------------
// P R O V I S I O N   A I K
//-------------------------------------------------------------------------------------------------
// The goal of ProvisionAttestationIdentityKey task is to create an aik that can be used to support
// tpm quotes.  This includes a number of 'handshakes' with HVS where nonces are exchanged to make
// sure the TPM/aik is valid.
//
// The handshake steps are...
// 1.) Send HVS an IdentityChallengeRequest that contains aik data and encrypted EK data (using HVS'
// privacy-ca) in niarl binary format.
//     POST IdentityChallengeRequest to https://server.com:8443/hvs/v2/privacyca/identity-challenge-request
// 2.) Receive back an IdentityProofRequest that includes an encrypted nonce that is decrypted by
// the TPM/aik (via 'ActivateCredential').
// 3.) Send the nonce back to HVS (encrypted by the HVS privacy-ca). If the nonce checks out, HVS
// responds with an (encrypted) aik cert that is saved to /opt/trustagent/configuration/aik.cer.
//    POST 'decrypted bytes' to https://server.com:8443/hvs/v2/privacyca/identity-challenge-response
//
// The 'aik.cer' is served via the /v2/aik endpoint and included in /tpm/quote.
//
// Throughout this process, the TPM is being provisioned with the aik so that calls to /tpm/quote
// will be successful.  QUOTES WILL NOT WORK IF THE TPM IS NOT PROVISIONED CORRECTLY.
//-------------------------------------------------------------------------------------------------

type ProvisionAttestationIdentityKey struct {
	TpmF                 tpmprovider.TpmFactory
	tpmp                 tpmprovider.TpmProvider
	ClientFactory        hvsclient.HVSClientFactory
	OwnerSecretKey       string
	EndorsementSecretKey string
	envPrefix            string
	commandName          string
	PrivacyCA            string
	AikCert              string
}

func (task *ProvisionAttestationIdentityKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, provisionAttestationIdentityKeyEnvHelpPrompt, "", provisionAttestationIdentityKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *ProvisionAttestationIdentityKey) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

func (task *ProvisionAttestationIdentityKey) Run() error {
	log.Trace("tasks/provision_aik:Run() Entering")
	defer log.Trace("tasks/provision_aik:Run() Leaving")
	fmt.Println("Running setup task: provision-aik")
	var err error

	task.tpmp, err = task.TpmF.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}
	defer task.tpmp.Close()

	privacyCAClient, err := task.ClientFactory.PrivacyCAClient()
	if err != nil {
		return errors.Wrap(err, "Failed to create privacycaClient-client")
	}

	// read the EK certificate and fail if not present...
	ekCertBytes, err := util.GetEndorsementKeyCertificateBytes(task.OwnerSecretKey, task.TpmF)
	if err != nil {
		return errors.Wrap(err, "Failed to get the endorsement certificate from the TPM")
	}

	// generate the aik in the tpm
	err = task.createAik()
	if err != nil {
		return errors.Wrap(err, "Failed to create AIK")
	}

	// create an IdentityChallengeRequest and populate it with aik information
	identityChallengeRequest := taModel.IdentityChallengePayload{}
	err = task.populateIdentityRequest(&identityChallengeRequest.IdentityRequest)
	if err != nil {
		return errors.Wrap(err, "Failed to populate the identity request")
	}

	privacyCaCert, err := util.GetPrivacyCA(task.PrivacyCA)
	if err != nil {
		return errors.Wrap(err, "Error while retrieving privacycaClient certificate")
	}

	privacycaClient, err := privacyca.NewPrivacyCA(identityChallengeRequest.IdentityRequest)
	if err != nil {
		return errors.Wrap(err, "Unable to get new privacycaClient instance")
	}

	// Get the Identity challenge request
	identityChallengeRequest, err = privacycaClient.GetIdentityChallengeRequest(ekCertBytes, privacyCaCert, identityChallengeRequest.IdentityRequest)
	if err != nil {
		return errors.Wrap(err, "Failed to encrypt the endorsement certificate")
	}

	// send the 'challenge request' to HVS and get an 'proof request' back
	identityProofRequest, err := privacyCAClient.GetIdentityProofRequest(&identityChallengeRequest)
	if err != nil {
		return errors.Wrap(err, "HVS returned an error while processing the identity proof request")
	}

	// pass the HVS response to the TPM to 'activate' the 'credential' and decrypt
	// the nonce created by HVS (IdentityProofRequest 'sym_blob')
	decrypted1, err := task.activateCredential(identityProofRequest)
	if err != nil {
		return errors.Wrap(err, "tasks/provision_aik:Run() Error while performing activate credential")
	}
	log.Debug("tasks/provision_aik:Run() Activate credential is successful for identity challenge request")

	// create an IdentityChallengeResponse to send back to HVS
	identityChallengeResponse := taModel.IdentityChallengePayload{}

	err = task.populateIdentityRequest(&identityChallengeResponse.IdentityRequest)
	if err != nil {
		return errors.Wrap(err, "Failed to populate the identity challenge response")
	}

	identityChallengeResponse, err = privacycaClient.GetIdentityChallengeRequest(decrypted1, privacyCaCert, identityChallengeResponse.IdentityRequest)
	if err != nil {
		return errors.Wrap(err, "Failed to retrieve the identity challenge from HVS")
	}

	// send the decrypted nonce data back to HVS and get a 'proof request' back
	identityProofRequest2, err := privacyCAClient.GetIdentityProofResponse(&identityChallengeResponse)
	if err != nil {
		return errors.Wrap(err, "HVS returned an error while processing the identity proof response")
	}

	// decrypt the 'proof request' from HVS into the 'aik' cert
	decrypted2, err := task.activateCredential(identityProofRequest2)
	if err != nil {
		return errors.Wrap(err, "Failed to activate credential")
	}

	log.Debug("tasks/provision_aik:Run() Activate credential is successful for identity challenge response")

	// make sure the decrypted bytes are a valid certificates...
	_, err = x509.ParseCertificate(decrypted2)
	if err != nil {
		return errors.Wrap(err, "The decrypted AIK is not a valid x509 certificate")
	}

	certOut, err := cos.OpenFileSafe(task.AikCert, "", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return errors.Wrapf(err, "Could not create file %s", task.AikCert)
	}
	defer func() {
		err = certOut.Close()
	}()

	if err := pem.Encode(certOut, &pem.Block{Type: CertificatePemBlockHeader, Bytes: decrypted2}); err != nil {
		return errors.Wrap(err, "Could not encode the AIK to pem")
	}

	return nil
}

func (task *ProvisionAttestationIdentityKey) Validate() error {
	log.Trace("tasks/provision_aik:Validate() Entering")
	defer log.Trace("tasks/provision_aik:Validate() Leaving")

	if _, err := os.Stat(task.AikCert); os.IsNotExist(err) {
		return errors.Wrap(err, "The aik certificate was not created")
	}

	log.Debug("tasks/provision_aik:Validate() Provisioning the AIK was successful.")
	return nil
}

func (task *ProvisionAttestationIdentityKey) createAik() error {
	log.Trace("tasks/provision_aik:createAik() Entering")
	defer log.Trace("tasks/provision_aik:createAik() Leaving")

	// KWT:  Update WLA to not use this file (the AIK is generally accessible without auth)

	//
	// Create an EK that will be used to generate the AIK...
	//
	err := task.tpmp.CreateEk(task.OwnerSecretKey, task.EndorsementSecretKey, tpmprovider.TPM_HANDLE_EK)
	if err != nil {
		return errors.Wrap(err, "Error while creating EK")
	}

	//
	// Compare the new EK's public key with the public key of the EK Certificate, if they don't
	// match then report an error to avoid downstream failures when communicating with HVS.
	//
	isValidEk, err := task.tpmp.IsValidEk(task.OwnerSecretKey, tpmprovider.TPM_HANDLE_EK, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return errors.Wrap(err, "Error validating EK")
	}

	if !isValidEk {
		return errors.Errorf("The EK at handle 0x%x does not have a public key that matches the EK Certificate at 0x%x", tpmprovider.TPM_HANDLE_EK, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	}

	//
	// create the AIK...
	//
	err = task.tpmp.CreateAik(task.OwnerSecretKey, task.EndorsementSecretKey)
	if err != nil {
		return errors.Wrap(err, "Error while creating AIK")
	}

	return nil
}

func (task *ProvisionAttestationIdentityKey) populateIdentityRequest(identityRequest *taModel.IdentityRequest) error {
	log.Trace("tasks/provision_aik:populateIdentityRequest() Entering")
	defer log.Trace("tasks/provision_aik:populateIdentityRequest() Leaving")

	// get the aik's public key and populate into the identityRequest
	aikPublicKeyBytes, err := task.tpmp.GetAikBytes()
	if err != nil {
		return err
	}

	identityRequest.AikModulus = aikPublicKeyBytes
	identityRequest.TpmVersion = "2.0" // Assume TPM 2.0 for GTA (1.2 is no longer supported)
	identityRequest.AikName, err = task.tpmp.GetAikName()
	if err != nil {
		return errors.Wrap(err, "Error while retrieving Aik Name from tpm")
	}

	return nil
}

//   - Input: IdentityProofRequest (Secret, Credential, SymmetricBlob, EndorsementCertifiateBlob)
//     HVS has encrypted a nonce in the SymmetricBlob
//   - Pass the Credential and Secret to TPM (ActivateCredential) and get the symmetric key back
//   - Proof Request Data
//   - Secret: made from this host's public EK in Tpm2.makeCredential
//   - Credential: made from this host's public EK in Tpm2.makeCredential
//   - SymmetricBlob
//   - int32 length of encrypted blob
//   - TpmKeyParams
//   - int32 algo id (TpmKeyParams.TPM_ALG_AES)
//   - short encoding scheme (TpmKeyParams.TPM_ES_NONE)
//   - short signature scheme (0)
//   - size of params (0)
//   - Encrypted Blob
//   - iv (16 bytes)
//   - encrypted bytes (encrypted blob length - 16 (iv))
//   - EndorsementKeyBlob:  SHA256 of this node's EK public using the Aik modules
//   - Use the symmetric key to decrypt the nonce (also requires iv) created by PrivacyCa.java::processV20
func (task *ProvisionAttestationIdentityKey) activateCredential(identityProofRequest *taModel.IdentityProofRequest) ([]byte, error) {
	log.Trace("tasks/provision_aik:activateCredential() Entering")
	defer log.Trace("tasks/provision_aik:activateCredential() Leaving")

	//
	// Read the credential bytes from the identityProofRequest
	// The bytes returned by HVS hava 2 bytes short of the length of the credential (TCG spec).
	// Could probably do a slice (i.e. [2:]) but let's read the length and validate the length.
	//
	var credentialSize uint16
	buf := bytes.NewBuffer(identityProofRequest.Credential)
	err := binary.Read(buf, binary.BigEndian, &credentialSize)
	if err != nil {
		return nil, errors.Wrap(err, "Error while reading credential size")
	}
	if credentialSize == 0 || int(credentialSize) > len(identityProofRequest.Credential) {
		return nil, errors.Errorf("Invalid credential size %d", credentialSize)
	}
	credentialBytes := buf.Next(int(credentialSize))
	//
	// Read the secret bytes similar to credential (i.e. with 2 byte size header)
	//
	var secretSize uint16
	buf = bytes.NewBuffer(identityProofRequest.Secret)
	err = binary.Read(buf, binary.BigEndian, &secretSize)
	if err != nil {
		return nil, errors.Wrap(err, "Error while reading secret size")
	}
	if secretSize == 0 || int(secretSize) > len(identityProofRequest.Secret) {
		return nil, errors.Errorf("Invalid secretSize size %d", secretSize)
	}

	secretBytes := buf.Next(int(secretSize))
	log.Debugf("tasks/provision_aik:activateCredential() secretBytes: %d", len(secretBytes))
	//
	// Now decrypt the symmetric key using ActivateCredential
	//
	symmetricKey, err := task.tpmp.ActivateCredential(task.EndorsementSecretKey, credentialBytes, secretBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error while performing tpm activate credential operation")
	}

	//   - SymmetricBlob
	//     - int32 length of encrypted blob
	//     - TpmKeyParams
	//       - int32 algo id (TpmKeyParams.TPM_ALG_AES)
	//       - short encoding scheme (TpmKeyParams.TPM_ES_NONE)
	//       - short signature scheme (0)
	//       - int32 size of params (0)
	//     - Encrypted Blob
	//       - iv (16 bytes)
	//       - encrypted bytes (encrypted blob length - 16 (iv))

	encryptedBytes := identityProofRequest.SymmetricBlob
	algoId := identityProofRequest.TpmSymmetricKeyParams.TpmAlgId
	encSchem := identityProofRequest.TpmSymmetricKeyParams.TpmAlgEncScheme
	sigSchem := identityProofRequest.TpmSymmetricKeyParams.TpmAlgSignatureScheme
	iv := identityProofRequest.TpmSymmetricKeyParams.IV

	log.Debugf("tasks/provision_aik:activateCredential() Algo[%d], Enc[%d], sig[%d]", algoId, encSchem, sigSchem)

	// decrypt the symblob using the symmetric key
	block, err := aes.NewCipher(symmetricKey)
	if err != nil {
		return nil, err
	}

	decrypted := make([]byte, len(encryptedBytes))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decrypted, encryptedBytes)

	length := len(decrypted)
	unpadding := int(decrypted[length-1])
	decrypted = decrypted[:(length - unpadding)]

	return decrypted, nil
}
