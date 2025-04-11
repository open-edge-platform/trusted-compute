/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import (
	"github.com/beevik/etree"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestGenLegacyAssertion(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	f := NewLegacyMapFormatter(testMap)
	root, err := f.generateXMLTree(IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
	})
	if err != nil || root == nil {
		t.Fatal("xml tree generate failed")
	}
	docBeforeSign := etree.NewDocument()
	docBeforeSign.SetRoot(root)
	docStr, err := docBeforeSign.WriteToString()
	if err != nil {
		t.Error("Failed to create unsigned document:", err.Error())
		t.Fail()
	}
	t.Log("Unsigned document:")
	t.Log(docStr)
}

func TestLegacyGenAndSign(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}
	k, c, err := genKeyAndCert()
	if err != nil {
		t.Fatal("Failed to generate rsa key:", err.Error())
	}
	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        k,
		Certificate:       c,
	}
	testSAML, err := NewLegacySAML(testIc)
	if err != nil {
		t.Fatal("Failed to create saml object:", err.Error())
	}
	testFormatter := NewLegacyMapFormatter(testMap)
	assertion, err := testSAML.GenerateSamlAssertion(testFormatter)
	if err != nil {
		t.Fatal("Failed to create saml assertion:", err.Error())
	}
	t.Log(assertion)

	// validate
	v, err := ValidateLegacySamlAssertion(assertion, c)
	if err != nil {
		t.Fatal("Failed to validate saml assertion:", err.Error())
	}
	doc := etree.NewDocument()
	doc.SetRoot(v)
	str, err := doc.WriteToString()
	if err != nil {
		t.Fatal("Failed to write validated saml assertion to string", err.Error())
	}
	t.Log(str)
}

func TestLegacyInvalidSamlSig(t *testing.T) {
	testMap := map[string]string{
		"test-field-1": "test-val-1",
		"test-field-2": "test-val-2",
		"test-field-3": "test-val-3",
		"test-field-4": "test-val-4",
		"test-field-5": "test-val-5",
	}

	k, c, err := genKeyAndCert()
	if err != nil {
		t.Fatal("Failed to generate rsa key:", err.Error())
	}

	testIc := IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        k,
		Certificate:       c,
	}
	testFormatter := NewLegacyMapFormatter(testMap)

	ss := legacySamlSigner{
		issuerConfig:     testIc,
		validityDuration: time.Second * time.Duration(testIc.ValiditySeconds),
		certBytes:        testIc.Certificate.Raw,
	}
	assertion, err := GenerateSamlAssertionWithoutSig(testFormatter, ss)
	if err != nil {
		t.Fatal("Failed to create saml assertion:", err.Error())
	}
	t.Log(assertion)

	// validate legacy saml assertion
	_, err = ValidateLegacySamlAssertion(assertion, c)
	t.Log(err)
	assert.NotNil(t, err)
	assert.Error(t, err)
}

// GenerateSamlAssertion generates SAML assertion with the input XML formatter
func GenerateSamlAssertionWithoutSig(f assertionFormatter, ss legacySamlSigner) (SamlAssertion, error) {
	r := SamlAssertion{}
	// generate xml tree from formatter
	xml, err := f.generateXMLTree(ss.issuerConfig)
	if err != nil {
		return r, errors.Wrap(err, "Failed to generate XML tree for signing")
	}

	// create xml document from the tree
	docAfterSign := etree.NewDocument()
	docAfterSign.SetRoot(xml)
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
