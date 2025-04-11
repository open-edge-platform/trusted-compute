/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package privacyca_test

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/tpm2utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	wlaModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

var aikModulus, _ = base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
var aikName, _ = base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq0QzsUHFRMsV0m5lcmRK4SLrzdRA==")

var identityReq = taModel.IdentityRequest{
	TpmVersion: "2.0",
	AikModulus: aikModulus,
	AikName:    aikName,
}

var publicKeyModulus, _ = base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
var tpmCertifyKey, _ = base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
var tpmCertifyKeySignature, _ = base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
var nameDigest, _ = base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
var aikCertificate, _ = crypt.GetRandomBytes(16)

var regKeyInfoPayload = wlaModel.RegisterKeyInfo{
	PublicKeyModulus:       publicKeyModulus,
	TpmCertifyKey:          tpmCertifyKey[2:],
	TpmCertifyKeySignature: tpmCertifyKeySignature,
	AikDerCertificate:      aikCertificate,
	NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
	TpmVersion:             "2.0",
	OsType:                 "Linux",
}

func TestProcessMakeCredential(t *testing.T) {
	privKey, certStr, err := crypt.CreateSelfSignedCertAndRSAPrivKeys(2048)
	assert.NoError(t, err)
	block, _ := pem.Decode([]byte(certStr))
	cert, err := x509.ParseCertificate(block.Bytes)
	assert.NoError(t, err)

	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

	//Generate identityChallengeNonce
	identityChallengeNonce, _ := crypt.GetRandomBytes(32)
	identityRequest := model.IdentityRequest{
		TpmVersion: "2.0",
		AikName: []byte{0, 11, 63, 66, 56, 152, 253, 128, 164, 49, 231, 162, 169, 14, 118, 72, 248, 151, 117, 166, 215,
			235, 210, 181, 92, 167, 94, 113, 24, 131, 10, 5, 12, 85, 252},
	}

	privacycaTpm2, err := privacyca.NewPrivacyCA(identityRequest)

	tpm2IdentityProofReq, err := privacycaTpm2.ProcessIdentityRequest(identityRequest, rsaPublicKey, identityChallengeNonce)
	assert.NoError(t, err)
	indentityBuf := new(bytes.Buffer)
	binary.Write(indentityBuf, binary.BigEndian, []byte(consts.IDENTITY))
	binary.Write(indentityBuf, binary.BigEndian, byte(0))

	//Get the seed using asymmetric decryption
	var encryptedSecretLength int16
	buf := bytes.NewBuffer(tpm2IdentityProofReq.Secret)
	binary.Read(buf, binary.BigEndian, &encryptedSecretLength)
	assert.Equal(t, 256, int(encryptedSecretLength))
	secret := buf.Next(int(encryptedSecretLength))
	assert.Equal(t, 256, len(secret))

	seed, err := tpm2utils.Tpm2DecryptAsym(secret, privKey, consts.TPM_ALG_ID_SHA256, indentityBuf.Bytes())
	assert.NoError(t, err)

	//Derive the symmetric key using seed
	symKey, err := tpm2utils.KDFa(crypto.SHA256, seed, consts.STORAGE, identityRequest.AikName, nil, 128)

	var encryptedCredentialLength int16
	var integrityLength int16
	buf = bytes.NewBuffer(tpm2IdentityProofReq.Credential)
	binary.Read(buf, binary.BigEndian, &encryptedCredentialLength)
	binary.Read(buf, binary.BigEndian, &integrityLength)
	buf.Next(int(integrityLength))
	encryptedCredential := buf.Next(int(encryptedCredentialLength) - int(integrityLength) - consts.SHORT_BYTES)
	iv := make([]byte, aes.BlockSize)

	//Decrypt the encryptedCredential for getting the symmetric key from which the symmetric key for decrypting the identityChallengeNonce can be decrypted
	key, err := tpm2utils.DecryptSym(encryptedCredential, symKey, iv, "CBF", consts.TPM_ALG_AES)
	assert.NoError(t, err)
	buf = bytes.NewBuffer(key)
	binary.Read(buf, binary.BigEndian, &encryptedCredentialLength)
	key = buf.Next(int(encryptedCredentialLength))
	symmetricBlob := tpm2IdentityProofReq.SymmetricBlob
	buf = bytes.NewBuffer(symmetricBlob)
	iv = tpm2IdentityProofReq.TpmSymmetricKeyParams.IV

	//Decrypt the credential secret to retrieve identityChallengeNonce
	dataBlob, err := tpm2utils.DecryptSym(symmetricBlob, key, iv, "CBC", consts.TPM_ALG_AES)
	assert.NoError(t, err)

	assert.Equal(t, dataBlob, identityChallengeNonce)
}

func TestGetEkCert(t *testing.T) {
	privacyCA, err := privacyca.NewPrivacyCA(identityReq)
	assert.NoError(t, err)
	cert, key, _ := crypt.CreateKeyPairAndCertificate(constants.DefaultPrivacyCaIdentityIssuer, "", constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)

	identityChallengeRequest := taModel.IdentityChallengePayload{}
	identityChallengeRequest.IdentityRequest = identityReq
	privKey, err := x509.ParsePKCS8PrivateKey(key)
	pubkey, err := x509.ParseCertificate(cert)
	ekCertBytes, _ := crypt.GetRandomBytes(16)
	idPayload, err := privacyCA.GetIdentityChallengeRequest(ekCertBytes, pubkey.PublicKey.(*rsa.PublicKey), identityReq)
	assert.NoError(t, err)
	_, err = privacyCA.GetEkCert(idPayload, privKey)
	assert.NoError(t, err)
}

func TestPrivacyCAForUnsupportedTpm(t *testing.T) {
	identityReq.TpmVersion = "1.0"
	_, err := privacyca.NewPrivacyCA(identityReq)
	assert.Error(t, err)
}

func TestValidateNameDigest(t *testing.T) {

	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)

	err = certifyKey20.ValidateNameDigest()
	assert.NoError(t, err)
}

func TestIsCertifiedKeySignatureValid(t *testing.T) {
	n := new(big.Int)
	n.SetBytes(aikModulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	certder, keyder, _ := crypt.CreateKeyPairAndCertificate(constants.DefaultPrivacyCaIdentityIssuer, "", constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
	privKey, _ := x509.ParsePKCS8PrivateKey(keyder)
	cert, _ := x509.ParseCertificate(certder)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	clientCRTTemplate := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "HVS",
		},
		SerialNumber: serialNumber,
	}

	aikCert, _ := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cert, &aikPubKey, privKey.(*rsa.PrivateKey))

	regKeyInfoPayload := wlaModel.RegisterKeyInfo{
		PublicKeyModulus:       publicKeyModulus,
		TpmCertifyKey:          tpmCertifyKey[2:],
		TpmCertifyKeySignature: tpmCertifyKeySignature,
		AikDerCertificate:      aikCert,
		NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
		TpmVersion:             "2.0",
		OsType:                 "Linux",
	}

	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)

	aik, err := x509.ParseCertificate(regKeyInfoPayload.AikDerCertificate)
	valid, err := certifyKey20.IsCertifiedKeySignatureValid(aik)
	assert.Equal(t, valid, true)
}

func TestIsCertifiedKeySignatureValidWithBadSignature(t *testing.T) {
	n := new(big.Int)
	n.SetBytes(aikModulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	certder, keyder, _ := crypt.CreateKeyPairAndCertificate(constants.DefaultPrivacyCaIdentityIssuer, "", constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
	privKey, _ := x509.ParsePKCS8PrivateKey(keyder)
	cert, _ := x509.ParseCertificate(certder)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)

	clientCRTTemplate := x509.Certificate{
		Issuer: pkix.Name{
			CommonName: "HVS",
		},
		SerialNumber: serialNumber,
	}

	aikCert, _ := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, cert, &aikPubKey, privKey.(*rsa.PrivateKey))

	regKeyInfoPayload.AikDerCertificate = aikCert
	//tamper signature
	regKeyInfoPayload.TpmCertifyKeySignature, _ = base64.StdEncoding.DecodeString("ABQACvEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9DrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)

	aik, _ := x509.ParseCertificate(regKeyInfoPayload.AikDerCertificate)

	valid, err := certifyKey20.IsCertifiedKeySignatureValid(aik)
	assert.Error(t, err)
	assert.Equal(t, valid, false)
}

func TestValidatePublicKey(t *testing.T) {
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)
	isKeyValid, err := certifyKey20.ValidatePublicKey()
	assert.NoError(t, err)
	assert.Equal(t, isKeyValid, true)
}

func TestIsTpmGeneratedKey(t *testing.T) {
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)
	assert.Equal(t, certifyKey20.IsTpmGeneratedKey(), true)
}

func TestIsTpmGeneratedKeyWithBadMagic(t *testing.T) {
	regKeyInfoPayload.TpmCertifyKey, _ = base64.StdEncoding.DecodeString("AJH/VEMHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)
	assert.Equal(t, certifyKey20.IsTpmGeneratedKey(), false)
}

func TestCertifyKey(t *testing.T) {
	n := new(big.Int)
	n.SetBytes(aikModulus)

	aikPubKey := rsa.PublicKey{N: n, E: 65537}
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)
	certder, keyder, _ := crypt.CreateKeyPairAndCertificate(constants.DefaultPrivacyCaIdentityIssuer, "", constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
	privKey, _ := x509.ParsePKCS8PrivateKey(keyder)
	cert, _ := x509.ParseCertificate(certder)

	_, err = certifyKey20.CertifyKey(cert, &aikPubKey, privKey.(*rsa.PrivateKey), "SigningKey")
	assert.NoError(t, err)
}

func TestGetPublicKeyFromModulus(t *testing.T) {
	certifyKey20, err := privacyca.NewCertifyKey(regKeyInfoPayload)
	assert.NoError(t, err)
	_, err = certifyKey20.GetPublicKeyFromModulus()
	assert.NoError(t, err)
}
