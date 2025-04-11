/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"time"

	"github.com/beevik/etree"
	rtvalidator "github.com/mattermost/xml-roundtrip-validator"
	"github.com/pkg/errors"
	dsig "github.com/russellhaering/goxmldsig"
)

type legacySamlSigner struct {
	issuerConfig     IssuerConfiguration
	validityDuration time.Duration
	certBytes        []byte
}

type legacyMapFormatter struct {
	userData map[string]string
}

// NewLegacySAML returns an exported interface SamlSigner configured
// according to input IssuerConfiguration
func NewLegacySAML(ic IssuerConfiguration) (SamlSigner, error) {
	r := legacySamlSigner{}
	if ic.IssuerName == "" {
		return r, errors.New("Invalid IssuerName for IssuerConfiguration")
	}
	if ic.IssuerServiceName == "" {
		return r, errors.New("Invalid IssuerServiceName for IssuerConfiguration")
	}
	if ic.ValiditySeconds == 0 {
		return r, errors.New("Invalid ValiditySeconds for IssuerConfiguration")
	}
	if ic.PrivateKey == nil {
		return r, errors.New("No private key assigned to issuer configuration")
	}
	if ic.Certificate == nil {
		return r, errors.New("No certificate assigned to issuer configuration")
	}
	r.issuerConfig = ic
	r.validityDuration = time.Second * time.Duration(ic.ValiditySeconds)
	r.certBytes = ic.Certificate.Raw
	return r, nil
}

// GetKeyPair returns the RSA key pair for signing the assertion
func (ss legacySamlSigner) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return ss.issuerConfig.PrivateKey, ss.certBytes, nil
}

// GenerateSamlAssertion generates SAML assertion with the input XML formatter
func (ss legacySamlSigner) GenerateSamlAssertion(f assertionFormatter) (SamlAssertion, error) {
	r := SamlAssertion{}
	// generate xml tree from formatter
	xml, err := f.generateXMLTree(ss.issuerConfig)
	if err != nil {
		return r, errors.Wrap(err, "Failed to generate XML tree for signing")
	}
	// sign the xml tree
	signedTree, err := signXMLTreeLegacy(ss, xml)
	if err != nil {
		return r, err
	}

	newSignedTree := reorderTree(signedTree)
	// create xml document from the tree
	docAfterSign := etree.NewDocument()
	docAfterSign.SetRoot(newSignedTree)
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

func reorderTree(signedTree *etree.Element) *etree.Element {
	var signElementPos int
	var issuerElement int
	for i, node := range signedTree.Child {
		if node == signedTree.SelectElement("Signature") {
			signElementPos = i
		}
		if node == signedTree.SelectElement("saml2:Issuer") {
			issuerElement = i
		}
	}
	//Move Signature next to issuer
	signElement := signedTree.SelectElement("Signature")
	signedTree.RemoveChildAt(signElementPos)
	signedTree.InsertChildAt(issuerElement+1, signElement)
	return signedTree
}

// NewLegacyMapFormatter returns an unexported interface assertionFormatter
// that formats XML tree according to input map
func NewLegacyMapFormatter(data map[string]string) assertionFormatter {
	return &legacyMapFormatter{
		userData: data,
	}
}

func (mf *legacyMapFormatter) generateXMLTree(ic IssuerConfiguration) (*etree.Element, error) {
	issueTime := time.Now().UTC().Format(rfc3339ms)
	d := time.Duration(ic.ValiditySeconds) * time.Second
	validTime := time.Now().Add(d).UTC().Format(rfc3339ms)
	// xml tree root
	root := etree.NewElement("saml2:Assertion")
	root.CreateAttr("ID", "MapAssertion")
	root.CreateAttr("IssueInstant", issueTime)
	root.CreateAttr("Version", "2.0")
	root.CreateAttr("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion")

	// issuer
	issuer := etree.NewElement("saml2:Issuer")
	issuer.CreateText(ic.IssuerName)
	root.AddChild(issuer)

	// subject
	subject := etree.NewElement("saml2:Subject")
	subjectNameID := etree.NewElement("saml2:NameID")
	subjectNameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	subjectNameID.CreateText(ic.IssuerServiceName)

	// subject confirmation
	subjectConfirmation := etree.NewElement("saml2:SubjectConfirmation")
	subjectConfirmation.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches")
	subjectConfirmationNameID := etree.NewElement("saml2:NameID")
	subjectConfirmationNameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
	subjectConfirmationData := etree.NewElement("saml2:SubjectConfirmationData")
	subjectConfirmationData.CreateAttr("NotBefore", issueTime)
	subjectConfirmationData.CreateAttr("NotOnOrAfter", validTime)
	subjectConfirmation.AddChild(subjectConfirmationNameID)
	subjectConfirmation.AddChild(subjectConfirmationData)

	subject.AddChild(subjectNameID)
	subject.AddChild(subjectConfirmation)
	root.AddChild(subject)

	// attribute statement
	attributeStatement := etree.NewElement("saml2:AttributeStatement")
	for k, v := range mf.userData {
		attribute := etree.NewElement("saml2:Attribute")
		attribute.CreateAttr("Name", k)
		attributeValue := etree.NewElement("saml2:AttributeValue")
		attributeValue.CreateAttr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
		attributeValue.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
		attributeValue.CreateAttr("xsi:type", "xsd:string")
		attributeValue.CreateText(v)
		attribute.AddChild(attributeValue)
		attributeStatement.AddChild(attribute)
	}
	root.AddChild(attributeStatement)
	return root, nil
}

// ValidateLegacySamlAssertion validates the input SAML-like assertion
// and returned the content as parsed XML element tree
func ValidateLegacySamlAssertion(sa SamlAssertion, root *x509.Certificate) (*etree.Element, error) {
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

func setNS(root *etree.Element, ns string) {
	if root == nil {
		return
	}
	root.Space = ns
	for _, c := range root.ChildElements() {
		setNS(c, ns)
	}
	return
}

func signXMLTreeLegacy(ks dsig.X509KeyStore, e *etree.Element) (*etree.Element, error) {
	ctx := &dsig.SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   dsig.DefaultIdAttr,
		Canonicalizer: dsig.MakeC14N10WithCommentsCanonicalizer(),
	}
	signedElement, err := ctx.SignEnveloped(e)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to sign XML tree")
	}
	return signedElement, nil
}
