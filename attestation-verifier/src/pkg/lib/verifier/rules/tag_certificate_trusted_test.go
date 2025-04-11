/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"crypto/x509"
	faultsConst "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestTagCertificateTrustedNoFault(t *testing.T) {

	// create a CA certpool...
	caPemBytes, caPrivateKey, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool()
	ok := trustedAuthorityCerts.AppendCertsFromPEM(caPemBytes)
	assert.True(t, ok)

	// create the attribute certificate...
	tagCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	tagCertificateBytes, err := getCertificateBytes(tagCertificate, caPrivateKey)
	assert.NoError(t, err)

	attributeCertificate := hvs.X509AttributeCertificate{
		Encoded:   tagCertificateBytes,
		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// create the rule
	rule, err := NewTagCertificateTrusted(trustedAuthorityCerts, &attributeCertificate)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on TagCertificateTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 0)
}

func TestTagCertificateTrustedMissingFault(t *testing.T) {

	// create a CA certpool...
	caPemBytes, _, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool()
	ok := trustedAuthorityCerts.AppendCertsFromPEM(caPemBytes)
	assert.True(t, ok)

	// create the rule, not provding the attribute certificate to invoke
	// FaultTagCertificateMissing.
	rule, err := NewTagCertificateTrusted(trustedAuthorityCerts, nil)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on TagCertificateTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, faultsConst.FaultTagCertificateMissing)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestTagCertificateTrustedNotTrusted(t *testing.T) {

	// create an empty CA certpool to force a FaultTagCertificateNotTrusted fault
	_, caPrivateKey, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool() // empty

	// create the attribute certificate...
	tagCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	tagCertificateBytes, err := getCertificateBytes(tagCertificate, caPrivateKey)
	assert.NoError(t, err)

	attributeCertificate := hvs.X509AttributeCertificate{
		Encoded:   tagCertificateBytes,
		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// create the rule
	rule, err := NewTagCertificateTrusted(trustedAuthorityCerts, &attributeCertificate)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on TagCertificateTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, faultsConst.FaultTagCertificateNotTrusted)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestTagCertificateTrustedExpiredFault(t *testing.T) {

	// create a CA certpool...
	caPemBytes, caPrivateKey, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool()
	ok := trustedAuthorityCerts.AppendCertsFromPEM(caPemBytes)
	assert.True(t, ok)

	// create the attribute certificate, providing a 'NotAfter' in the past
	// to invoke the FaultTagCertificateExpired fault.
	tagCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	tagCertificateBytes, err := getCertificateBytes(tagCertificate, caPrivateKey)
	assert.NoError(t, err)

	attributeCertificate := hvs.X509AttributeCertificate{
		Encoded:   tagCertificateBytes,
		NotBefore: time.Now().AddDate(-1, 0, 0),
		NotAfter:  time.Now().AddDate(-11, 0, 0),
	}

	// create the rule
	rule, err := NewTagCertificateTrusted(trustedAuthorityCerts, &attributeCertificate)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on TagCertificateTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, faultsConst.FaultTagCertificateExpired)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestTagCertificateTrustedNotYetValidFault(t *testing.T) {

	// create a CA certpool...
	caPemBytes, caPrivateKey, err := newCACertificate()
	assert.NoError(t, err)

	trustedAuthorityCerts := x509.NewCertPool()
	ok := trustedAuthorityCerts.AppendCertsFromPEM(caPemBytes)
	assert.True(t, ok)

	// create the attribute certificate, providing a 'NotBefore' in the future
	// to invoke the FaultTagCertificateNotYetValid fault.
	tagCertificate, err := newCertificateTemplate()
	assert.NoError(t, err)

	tagCertificateBytes, err := getCertificateBytes(tagCertificate, caPrivateKey)
	assert.NoError(t, err)

	attributeCertificate := hvs.X509AttributeCertificate{
		Encoded:   tagCertificateBytes,
		NotBefore: time.Now().AddDate(1, 0, 0),
		NotAfter:  time.Now().AddDate(1, 0, 0),
	}

	// create the rule
	rule, err := NewTagCertificateTrusted(trustedAuthorityCerts, &attributeCertificate)
	assert.NoError(t, err)

	// apply the rule, the hostManifest has no impact on TagCertificateTrusted rule
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, len(result.Faults), 1)
	assert.Equal(t, result.Faults[0].Name, faultsConst.FaultTagCertificateNotYetValid)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}
