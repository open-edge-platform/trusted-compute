/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFlavorTrustedNoFault(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	flavorSigningCertificate, flavorCaCertificates, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// create the rule
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, flavorCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
}

func TestFlavorTrustedNoFaultFromJSON(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	flavorSigningCertificate, flavorCaCertificates, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// validate that signatures work when they originate from flavor json.
	flavorJSON := `{
		  "meta": {
		    "id": "ff353e08-a5f0-4e32-b054-80ff79720d7d"
		  }
		}`

	var flavor hvs.Flavor
	err = json.Unmarshal([]byte(flavorJSON), &flavor)
	assert.NoError(t, err)

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// create the rule
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, flavorCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
}

func TestFlavorTrustedFlavorSignatureMissingFault(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	flavorSigningCertificate, flavorCaCertificates, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// now remove the signature to invoke FaultFlavorSignatureMissing
	signedFlavor.Signature = ""

	// create the rule
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, flavorCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultFlavorSignatureMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestFlavorTrustedMissingFlavorSigningCertificate(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	// the FlavorSigningCertificate will not be used in this test
	_, flavorCaCertificates, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// create the rule without the flavorSigningCertificate to invoke
	// FaultFlavorSignatureVerificationFailed
	rule, err := NewFlavorTrusted(signedFlavor, nil, flavorCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultFlavorSignatureVerificationFailed, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestFlavorTrustedMissingCACertificates(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	// the CAs will not be used in this test
	flavorSigningCertificate, _, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// create the rule without the CA certs to invoke
	// FaultFlavorSignatureVerificationFailed
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, nil, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultFlavorSignatureVerificationFailed, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestFlavorTrustedInvalidRootCA(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	// the CAs will not be used in this test
	flavorSigningCertificate, _, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a different/invalid CA certpool to invoke FaultFlavorSignatureVerificationFailed
	caPemBytes, privateKey, err := newCACertificate()
	assert.NoError(t, err)

	invalidCaCertificates := x509.NewCertPool()
	_ = invalidCaCertificates.AppendCertsFromPEM(caPemBytes)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// create the rule without the CA certs to invoke the
	// FaultFlavorSignatureVerificationFailed
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, invalidCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultFlavorSignatureVerificationFailed, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestFlavorTrustedForceSignatureVerificationToFail(t *testing.T) {

	// create all of the certs, private keys, CAs etc. to test the rule
	flavorSigningCertificate, flavorCaCertificates, privateKey, err := createCryptoResources()
	assert.NoError(t, err)

	// create a valid flavor and signed flavor
	flavor := hvs.Flavor{
		Meta: hvs.Meta{
			ID: testUuid,
		},
	}

	signedFlavor, err := hvs.NewSignedFlavor(&flavor, privateKey)
	assert.NoError(t, err)

	// now change the signature to force verification to fail
	signedFlavor.Signature = "invalidsignature"

	// create the rule
	rule, err := NewFlavorTrusted(signedFlavor, flavorSigningCertificate, flavorCaCertificates, hvs.FlavorPartPlatform)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on FlavorTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultFlavorSignatureNotTrusted, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func createCryptoResources() (*x509.Certificate, *x509.CertPool, *rsa.PrivateKey, error) {

	// create a CA certpool...
	caPemBytes, privateKey, err := newCACertificate()
	if err != nil {
		return nil, nil, nil, err
	}

	flavorCaCertificates := x509.NewCertPool()
	_ = flavorCaCertificates.AppendCertsFromPEM(caPemBytes)

	// create the flavor signing 'template'
	flavorSigningTemplate, err := newCertificateTemplate()
	if err != nil {
		return nil, nil, nil, err
	}

	// now get the bytes for the flavor signing certificate
	flavorSigningCertificateBytes, err := getCertificateBytes(flavorSigningTemplate, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// apparently you can't call 'certificate.Verify' if the cert
	// was not loaded from bytes ("asn.1 content missing; use ParseCertificate")
	flavorSigningCertificate, err := x509.ParseCertificate(flavorSigningCertificateBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	return flavorSigningCertificate, flavorCaCertificates, privateKey, nil
}
