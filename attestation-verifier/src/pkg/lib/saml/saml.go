/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import (
	"crypto/rsa"
	"crypto/x509"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	"strings"
	"time"
	"unicode"

	"github.com/beevik/etree"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
)

type SamlSigner interface {
	GenerateSamlAssertion(assertionFormatter) (SamlAssertion, error)
}

type defaultSamlSigner struct {
	issuerConfig     IssuerConfiguration
	validityDuration time.Duration
	certBytes        []byte
}

// NewSAML returns an exported interface SamlSigner configured
// according to input IssuerConfiguration
func NewSAML(ic IssuerConfiguration) (SamlSigner, error) {
	r := defaultSamlSigner{}
	if ic.IssuerName == "" {
		return nil, errors.New("Invalid IssuerName for IssuerConfiguration")
	}
	if ic.IssuerServiceName == "" {
		return nil, errors.New("Invalid IssuerServiceName for IssuerConfiguration")
	}
	if ic.ValiditySeconds == 0 {
		return nil, errors.New("Invalid ValiditySeconds for IssuerConfiguration")
	}
	if ic.PrivateKey == nil {
		return nil, errors.New("No private key assigned to issuer configuration")
	}
	if ic.Certificate == nil {
		return nil, errors.New("No certificate assigned to issuer configuration")
	}
	r.issuerConfig = ic
	r.validityDuration = time.Second * time.Duration(ic.ValiditySeconds)
	r.certBytes = ic.Certificate.Raw
	return &r, nil
}

// GetKeyPair returns the RSA key pair for signing the assertion
func (ss *defaultSamlSigner) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ss.issuerConfig.PrivateKey, ss.certBytes, nil
}

// GenerateSamlAssertion generates SAML assertion with the input XML formatter
func (ss *defaultSamlSigner) GenerateSamlAssertion(f assertionFormatter) (SamlAssertion, error) {
	r := SamlAssertion{}
	// generate xml tree from formatter
	xml, err := f.generateXMLTree(ss.issuerConfig)
	if err != nil {
		return r, errors.Wrap(err, "Failed to generate XML tree for signing")
	}
	// sign the xml tree
	signedTree, err := signXMLTree(ss, xml)
	if err != nil {
		return r, err
	}
	// create xml document from the tree
	docAfterSign := etree.NewDocument()
	docAfterSign.SetRoot(signedTree)
	signedDocStr, err := docAfterSign.WriteToString()
	if err != nil {
		return r, errors.Wrap(err, "Failed to create signed document")
	}
	// prepare the assertion
	r.Assertion = signedDocStr
	r.CreatedTime = time.Now().UTC()
	r.ExpiryTime = time.Now().UTC().Add(ss.validityDuration)
	return r, nil
}

// ValidateSamlAssertion validates the input SAML assertion and returned
// the content as parsed XML element tree
func ValidateSamlAssertion(sa SamlAssertion, root *x509.Certificate) (*etree.Element, error) {
	if root == nil {
		return nil, errors.New("No certificate provided")
	}
	docStr := sa.Assertion
	if docStr == "" ||
		!isASCII(docStr) {
		return nil, errors.New("Invalid XML string: non-ASCII charactors detected")
	}
	err := rtvalidator.Validate(strings.NewReader(docStr))
	if err != nil {
		return nil, errors.New("Invalid XML string: xml round-trip validation failed")
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(docStr); err != nil {
		return nil, errors.Wrap(err, "Failed to parse XML document")
	}
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{root},
	})

	// check if saml signature and value attributes exist
	if doc.Root().SelectElement("Signature") == nil || doc.Root().SelectElement("Signature").SelectElement("SignatureValue") == nil {
		return nil, errors.New("Signature and Signature value in SAML cannot be nil")
	}

	validated, err := ctx.Validate(doc.Root())
	if err != nil {
		return nil, errors.Wrap(err, "Failed to validate XML document")
	}
	return validated, nil
}

func signXMLTree(key dsig.X509KeyStore, e *etree.Element) (*etree.Element, error) {
	ctx := dsig.NewDefaultSigningContext(key)
	signedElement, err := ctx.SignEnveloped(e)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to sign XML tree")
	}
	return signedElement, nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
