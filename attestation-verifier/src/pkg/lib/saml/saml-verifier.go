/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package saml

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/beevik/etree"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"strings"
)

var log = commLog.GetDefaultLogger()

//VerifySamlSignature Verify Cert chain and SAML signature of the Report
func VerifySamlSignature(samlReport, SamlCertPath, CACertDirPath string) bool {

	log.Trace("saml/saml-verifier:VerifySamlSignature() Entering")
	defer log.Trace("saml/saml-verifier:VerifySamlSignature() Leaving")

	caCerts, err := crypt.GetCertsFromDir(CACertDirPath)
	if err != nil {
		log.WithError(err).Errorf("saml/saml-verifier:VerifySamlSignature() Error retrieving CA certificates from %s", CACertDirPath)
		return false
	}

	certPemSlice, err := crypt.GetSubjectCertsMapFromPemFile(SamlCertPath)
	if err != nil {
		log.WithError(err).Error("saml/saml-verifier:VerifySamlSignature() Error while retrieving SAML certificate")
		return false
	}

	verifyRootCAOpts := x509.VerifyOptions{
		Roots:         crypt.GetCertPool(caCerts),
		Intermediates: crypt.GetCertPool(certPemSlice[1:]),
	}

	var trustedCertChainFound bool
	for _, cert := range certPemSlice {

		if !(cert.IsCA && cert.BasicConstraintsValid) {
			if _, err := cert.Verify(verifyRootCAOpts); err != nil {
				continue
			} else {
				log.Debug("saml/saml-verifier:VerifySamlSignature() SAML certificate chain verification successful")
				trustedCertChainFound = true
				break
			}
		}
	}

	if !trustedCertChainFound {
		log.Error("saml/saml-verifier:VerifySamlSignature() Error verifying certificate chain for SAML certificate. No " +
			"valid certificate chain could be found")
		return false
	}

	pemBlock, _ := pem.Decode(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certPemSlice[0].Raw}))

	log.Debug("saml/saml-verifier:VerifySamlSignature() Validating saml signature from HVS")
	isValidated := validateSamlSignature(samlReport, pemBlock.Bytes)
	if !isValidated {
		log.Error("saml/saml-verifier:VerifySamlSignature() SAML signature verification failed")
		return false
	}

	log.Debug("saml/saml-verifier:VerifySamlSignature() Successfully validated SAML signature")
	return true
}

func validateSamlSignature(samlString string, samlCertBytes []byte) bool {
	log.Trace("saml/saml-verifier:validateSamlSignature() Entering")
	defer log.Trace("saml/saml-verifier:validateSamlSignature() Leaving")

	//this will be used to replace LF, CRLF from SAML report
	newLineReplacer := strings.NewReplacer("\n", "", "\r\n", "")
	samlReport := newLineReplacer.Replace(samlString)
	err := rtvalidator.Validate(strings.NewReader(samlReport))
	if err != nil {
		log.Error("saml/saml-verifier:validateSamlSignature() Invalid XML string: xml round-trip validation failed")
		return false
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(samlReport); err != nil {
		log.WithError(err).Error("saml/saml-verifier:validateSamlSignature() Failed to parse SAML report")
		return false
	}

	x509Cert, err := x509.ParseCertificate(samlCertBytes)
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{x509Cert},
	})

	// check if saml signature and value attributes exist
	if doc.Root().SelectElement("Signature") == nil || doc.Root().SelectElement("Signature").SelectElement("SignatureValue") == nil {
		log.Error("Signature and Signature value in SAML cannot be nil")
		return false
	}

	etreeElement, err := ctx.Validate(doc.Root())
	if err != nil || etreeElement == nil {
		log.WithError(err).Error("saml/saml-verifier:validateSamlSignature() Error verifying SAML signature ")
		return false
	}
	return true
}
