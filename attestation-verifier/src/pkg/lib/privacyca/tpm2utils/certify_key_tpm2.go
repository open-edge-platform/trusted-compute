/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpm2utils

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/constants"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	"github.com/pkg/errors"
	"math/big"
	"time"
)

var defaultLog = log.GetDefaultLogger()
var secLog = log.GetSecurityLogger()

type CertifyKey20 struct {
	RegKeyInfo model.RegisterKeyInfo
}

func (certifyKey20 *CertifyKey20) IsCertifiedKeySignatureValid(aikCert *x509.Certificate) (bool, error) {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Leaving")

	var signedSignatureBytes []byte
	tpmCertifyKeyBytes := certifyKey20.RegKeyInfo.TpmCertifyKey
	tpmCertifyKeySignatureBytes := certifyKey20.RegKeyInfo.TpmCertifyKeySignature

	var tpm2CertifyKey Tpm2CertifiedKey
	err := tpm2CertifyKey.PopulateTpmCertifyKey20(certifyKey20.RegKeyInfo.TpmCertifyKey)
	if err != nil {
		return false, errors.New("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Error populating TPM Certify Key")
	}

	hashAlg, _, err := tpm2CertifyKey.GetTpmtHashAlgDigest()
	if err != nil {
		return false, errors.New("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Error while getting hash algorithm from tpm certificate")
	}

	if len(tpmCertifyKeySignatureBytes) > 256 {
		defaultLog.Debug("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Length of certifyKeySignatureBlob is larger then 256, TPM 2.0. Will only parse out the required 256 bytes:")
		signedSignatureBytes = make([]byte, 256)
		signedSignatureBytes = tpmCertifyKeySignatureBytes[len(tpmCertifyKeySignatureBytes)-256:]
	} else {
		return false, errors.New("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Length of certifyKeySignatureBlob is 256 or less, TPM 1.2")
	}

	aikRsaPubKey := aikCert.PublicKey.(*rsa.PublicKey)
	if hashAlg != constants.TPM_ALG_ID_SHA256 {
		return false, errors.Errorf("tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Unsupported hash algorithm, hash alg ID: %d", hashAlg)
	}

	h := sha256.New()
	_, err = h.Write(tpmCertifyKeyBytes)
	if err != nil {
		return false, errors.Wrap(err, "tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Error writing key")
	}
	computedDigest := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(aikRsaPubKey, crypto.SHA256, computedDigest, signedSignatureBytes)
	if err != nil {
		return false, errors.Wrap(err, "tpm2utils/certify_key_tpm2:IsCertifiedKeySignatureValid() Error during signature verification.")
	}

	return true, nil
}

func (certifyKey20 *CertifyKey20) ValidateNameDigest() error {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:ValidateNameDigest() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:ValidateNameDigest() Leaving")

	nameDigest := certifyKey20.RegKeyInfo.NameDigest
	tcgCertificate := certifyKey20.RegKeyInfo.TpmCertifyKey
	padding, _ := hex.DecodeString(constants.Tpm2NameDigestPrefixPadding)
	endPadding, _ := hex.DecodeString(constants.Tpm2NameDigestSuffixPadding)

	var tpmCertifyKey20 Tpm2CertifiedKey
	err := tpmCertifyKey20.PopulateTpmCertifyKey20(tcgCertificate)
	if err != nil {
		return errors.Wrap(err, "tpm2utils/certify_key_tpm2:ValidateNameDigest() Error populating TPM Certify Key")
	}
	_, digest, err := tpmCertifyKey20.GetTpmtHashAlgDigest()
	if err != nil {
		return errors.Wrap(err, "tpm2utils/certify_key_tpm2:ValidateNameDigest() Error while extracting digest from tpm certified key")
	}
	digest = append(padding, digest...)
	digest = append(digest, endPadding...)
	if !bytes.Equal(digest, nameDigest) {
		return errors.New("tpm2utils/certify_key_tpm2:ValidateNameDigest() Name digest does not  match with digest in tpm certified key blob")
	}
	return nil
}

func (certifyKey20 *CertifyKey20) ValidatePublicKey() (bool, error) {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:ValidatePublicKey() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:ValidatePublicKey() Leaving")

	pubKeyMod := certifyKey20.RegKeyInfo.PublicKeyModulus
	tpmCertifiedKey := certifyKey20.RegKeyInfo.TpmCertifyKey
	var tpmCertifyKey20 Tpm2CertifiedKey
	err := tpmCertifyKey20.PopulateTpmCertifyKey20(tpmCertifiedKey)
	if err != nil {
		return false, errors.Wrap(err, "tpm2utils/certify_key_tpm2:ValidatePublicKey() Error populating TPM Certify Key")
	}
	//Get the public key digest from attestation info
	hashAlg, digest, err := tpmCertifyKey20.GetTpmtHashAlgDigest()
	if err != nil {
		return false, errors.Wrap(err, "tpm2utils/certify_key_tpm2:ValidatePublicKey() Error while extracting digest from tpm certified key")
	}
	//remove first two bytes that represent the public area size
	publicKeyInfoBuffer := pubKeyMod[2:]
	switch hashAlg {
	case constants.TPM_ALG_ID_SHA256:
		publicKeyInfoBufferDigest := sha256.Sum256(publicKeyInfoBuffer)
		if equal(publicKeyInfoBufferDigest[:], digest) {
			return true, nil
		}
	case constants.TPM_ALG_ID_SHA384:
		publicKeyInfoBufferDigest := sha512.Sum384(publicKeyInfoBuffer)
		if equal(publicKeyInfoBufferDigest[:], digest) {
			return true, nil
		}
	default:
		return false, errors.Wrapf(err, "tpm2utils/certify_key_tpm2:ValidatePublicKey() Hash algorithm:%d not supported", hashAlg)
	}
	return false, nil
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (certifyKey20 *CertifyKey20) GetPublicKeyFromModulus() (*rsa.PublicKey, error) {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:GetPublicKeyFromModulus() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:GetPublicKeyFromModulus() Leaving")

	rsaPubKeyModulus := certifyKey20.RegKeyInfo.PublicKeyModulus
	if len(rsaPubKeyModulus) < 256 {
		return nil, errors.New("tpm2utils/certify_key_tpm2:GetPublicKeyFromModulus() Received tpm binding key pub modulus is less than 256")
	}

	bigInt := big.NewInt(0)
	// Generate the TCG standard exponent to create the RSA public key from the modulus specified.
	pubExp := make([]byte, 3)
	pubExp[0] = (byte)(0x01 & 0xff)
	pubExp[1] = (byte)(0x00)
	pubExp[2] = (byte)(0x01 & 0xff)

	exponent := new(big.Int)
	exponent.SetBytes(pubExp)

	publicKeyModulusRSA := make([]byte, len(rsaPubKeyModulus))
	publicKeyModulusRSA = rsaPubKeyModulus[len(rsaPubKeyModulus)-256:]
	bigInt.SetBytes(publicKeyModulusRSA)
	pubKey := rsa.PublicKey{N: bigInt, E: int(exponent.Int64())}
	return &pubKey, nil
}

func (certifyKey20 *CertifyKey20) CertifyKey(caCert *x509.Certificate, rsaPubKey *rsa.PublicKey, caKey *rsa.PrivateKey, cn string) ([]byte, error) {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:CertifyKey() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:CertifyKey() Leaving")

	var extensions []pkix.Extension

	bcExt := pkix.Extension{Id: []int{2, 5, 4, 133, 3, 2, 41}, Critical: false, Value: certifyKey20.RegKeyInfo.TpmCertifyKey}
	bcExt1 := pkix.Extension{Id: []int{2, 5, 4, 133, 3, 2, 41, 1}, Critical: false, Value: certifyKey20.RegKeyInfo.TpmCertifyKeySignature}
	extensions = append(extensions, bcExt)
	extensions = append(extensions, bcExt1)

	serialNumber := getRandomSerialNumber()
	csrTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.SHA384WithRSA,
		PublicKey:          rsaPubKey,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(constants.HOST_KEYS_CERT_VALIDITY, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtraExtensions:    extensions,
	}

	certificate, err := x509.CreateCertificate(rand.Reader, &csrTemplate, caCert, rsaPubKey, caKey)
	if err != nil {
		return nil, errors.Wrap(err, "tpm2utils/certify_key_tpm2:CertifyKey() Cannot create certificate")
	}

	return certificate, nil
}

func getRandomSerialNumber() *big.Int {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	//Generate cryptographically strong pseudo-random between 0 - max
	n, _ := rand.Int(rand.Reader, max)
	return n
}

func (certifyKey20 *CertifyKey20) IsTpmGeneratedKey() bool {
	defaultLog.Trace("tpm2utils/certify_key_tpm2:IsTpmGeneratedKey() Entering")
	defer defaultLog.Trace("tpm2utils/certify_key_tpm2:IsTpmGeneratedKey() Leaving")

	var tpmCertifyKey20 Tpm2CertifiedKey
	err := tpmCertifyKey20.PopulateTpmCertifyKey20(certifyKey20.RegKeyInfo.TpmCertifyKey)
	if err != nil {
		secLog.WithError(err).Errorf("tpm2utils/certify_key_tpm2:IsTpmGeneratedKey() Coulld not populate Key")
		return false
	}
	if tpmCertifyKey20.Magic != constants.Tpm2CertifiedKeyMagic {
		secLog.Warnf("tpm2utils/certify_key_tpm2:IsTpmGeneratedKey() Invalid structure, it wasn't created by the TPM, got %s, expecting %s", tpmCertifyKey20.Magic, constants.Tpm2CertifiedKeyMagic)
		return false
	}

	if tpmCertifyKey20.Type != constants.Tpm2CertifiedKeyType {
		secLog.Warnf("tpm2utils/certify_key_tpm2:IsTpmGeneratedKey() Invalid type, got type: %s", tpmCertifyKey20.Type)
		return false
	}

	return true
}
