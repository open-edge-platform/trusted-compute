/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package privacyca

import (
	"crypto/rsa"
	"crypto/x509"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/privacyca/tpm2utils"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	"github.com/pkg/errors"
)

type CertifyKey interface {
	IsCertifiedKeySignatureValid(aikCert *x509.Certificate) (bool, error)
	ValidateNameDigest() error
	ValidatePublicKey() (bool, error)
	CertifyKey(caCert *x509.Certificate, rsaPubKey *rsa.PublicKey, caKey *rsa.PrivateKey, cn string) ([]byte, error)
	GetPublicKeyFromModulus() (*rsa.PublicKey, error)
	IsTpmGeneratedKey() bool
}

func NewCertifyKey(regKeyInfo model.RegisterKeyInfo) (CertifyKey, error) {
	log.Trace("privacyca/certify_key_factory:NewCertifyKey() Entering")
	defer log.Trace("privacyca/certify_key_factory:NewCertifyKey() Leaving")
	if regKeyInfo.TpmVersion == "2.0" {
		certifyKey20 := tpm2utils.CertifyKey20{
			RegKeyInfo: regKeyInfo,
		}
		return &certifyKey20, nil
	}

	return nil, errors.New("privacyca/certify_key_factory:NewCertifyKey() Unsupported tpm version")
}
