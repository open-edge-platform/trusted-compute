/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

//
// Contains 'public' structures, interfaces and factory methods available to external
// packages.
//

import (
	"crypto/x509"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// VerifierCertificates A collection of certificates/certificate pools that
// must be provide to the Verifier in NewVerifier().
type VerifierCertificates struct {
	PrivacyCACertificates    *x509.CertPool
	AssetTagCACertificates   *x509.CertPool
	FlavorSigningCertificate *x509.Certificate
	FlavorCACertificates     *x509.CertPool
}

// Verifier The interface that exposes the verification of a host manifest
// and signed flavor.  The 'skipFlavorsignatureVerfication' parameter can
// be used to disable the verification of the flavor signature.
type Verifier interface {
	Verify(hostManifest *hvs.HostManifest, signedFlavor *hvs.SignedFlavor, skipFlavorSignatureVerification bool) (*hvs.TrustReport, error)
	GetVerifierCerts() VerifierCertificates
}

// NewVerifier Creates a Verifier provided a valid set of verifierCertificates.
// An error is raised if any of the fields in VerifierCertificate is nil.
func NewVerifier(verifierCertificates VerifierCertificates) (Verifier, error) {

	if verifierCertificates.PrivacyCACertificates == nil {
		return nil, errors.New("The privacy CA certificates cannot be nil")
	}

	if verifierCertificates.AssetTagCACertificates == nil {
		return nil, errors.New("The asset tag ca cannot be nil")
	}

	if verifierCertificates.FlavorSigningCertificate == nil {
		return nil, errors.New("The flavor signing certificate cannot be nil")
	}

	if verifierCertificates.FlavorCACertificates == nil {
		return nil, errors.New("The flavor CA certificates cannot be nil")
	}

	return &verifierImpl{verifierCertificates: verifierCertificates}, nil
}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()
