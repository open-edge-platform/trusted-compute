/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hosttrust

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io/ioutil"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("SamlReport", func() {
	testIc := getIssuer()
	reportGen := NewSamlReportGenerator(testIc)

	verifierCertificates := createVerifierCertificates(
		"../../../lib/verifier/test_data/intel20/PrivacyCA.pem",
		"../../../lib/verifier/test_data/intel20/flavor-signer.crt.pem",
		"../../../lib/verifier/test_data/intel20/cms-ca-cert.pem",
		"../../../lib/verifier/test_data/intel20/tag-cacerts.pem")

	javaTrustReport := getTrustReport(
		"../../../lib/verifier/test_data/intel20/host_manifest.json",
		"../../../lib/verifier/test_data/intel20/signed_flavors.json",
		"../../../lib/verifier/test_data/intel20/trust_report.json",
		verifierCertificates)

	Describe("Generate SAML report", func() {
		Context("Given trust report and issuer details to SAML report generator", func() {
			It("Should generate SAML report", func() {
				assertion := reportGen.GenerateSamlReport(javaTrustReport)
				Expect(assertion).NotTo(BeNil())
				Expect(assertion.Assertion).ShouldNot(BeEmpty())
				log.Info("Generated SAML report : " + assertion.Assertion)
			})
		})
	})
})

func getIssuer() *saml.IssuerConfiguration {
	certBytes, privKeyDer, _ := crypt.CreateKeyPairAndCertificate("root-test", "", constants.DefaultKeyAlgorithm, constants.DefaultKeyLength)
	cert, _ := x509.ParseCertificate(certBytes)
	key, _ := x509.ParsePKCS8PrivateKey(privKeyDer)

	return &saml.IssuerConfiguration{
		IssuerName:        "http://idp.test.com/metadata.php",
		IssuerServiceName: "test-idp",
		ValiditySeconds:   100,
		PrivateKey:        key.(*rsa.PrivateKey),
		Certificate:       cert,
	}
}

func getTrustReport(
	hostManifestFile string,
	signedFlavorsFile string,
	trustReportFile string,
	verifierCertificates *verifier.VerifierCertificates) *hvs.TrustReport {

	var hostManifest hvs.HostManifest
	var signedFlavors []hvs.SignedFlavor
	var javaTrustReports map[string]hvs.TrustReport

	manifestJSON, _ := ioutil.ReadFile(hostManifestFile)
	json.Unmarshal(manifestJSON, &hostManifest)
	flavorsJSON, _ := ioutil.ReadFile(signedFlavorsFile)
	json.Unmarshal(flavorsJSON, &signedFlavors)
	v, _ := verifier.NewVerifier(*verifierCertificates)
	javaTrustReportsJSON, _ := ioutil.ReadFile(trustReportFile)
	json.Unmarshal(javaTrustReportsJSON, &javaTrustReports)

	var collectiveReport hvs.TrustReport
	for _, signedFlavor := range signedFlavors {
		trustReport, _ := v.Verify(&hostManifest, &signedFlavor, true)
		collectiveReport.Results = append(collectiveReport.Results, trustReport.Results...)
	}
	collectiveReport.HostManifest = hostManifest
	collectiveReport.Trusted = collectiveReport.IsTrusted()
	return &collectiveReport
}

func createVerifierCertificates(
	privacyCAFile string,
	flavorSignerCertFile string,
	cmsCAsFile string,
	tagCertsFile string) *verifier.VerifierCertificates {

	//
	// Privacy CA
	//
	log.Info("Privacy CA nil" + privacyCAFile)
	privacyCAsPemBytes, _ := ioutil.ReadFile(privacyCAFile)
	if privacyCAsPemBytes == nil {
		log.Info("Privacy CA nil" + privacyCAFile)
	}
	privacyCACertificates := x509.NewCertPool()
	privacyCACertificates.AppendCertsFromPEM(privacyCAsPemBytes)

	//
	// Flavor Signing
	//

	flavorSigningPemBytes, _ := ioutil.ReadFile(flavorSignerCertFile)
	flavorSigningCertificate, flavorCACertificates, _ := crypt.GetCertAndChainFromPem(flavorSigningPemBytes)
	flavorCAsPemBytes, _ := ioutil.ReadFile(cmsCAsFile)
	flavorCACertificates.AppendCertsFromPEM(flavorCAsPemBytes)

	//
	// Asset Tags
	//
	assetTagPemBytes, _ := ioutil.ReadFile(tagCertsFile)
	assetTagCACertificates := x509.NewCertPool()
	assetTagCACertificates.AppendCertsFromPEM(assetTagPemBytes)

	return &verifier.VerifierCertificates{
		PrivacyCACertificates:    privacyCACertificates,
		FlavorSigningCertificate: flavorSigningCertificate,
		AssetTagCACertificates:   assetTagCACertificates,
		FlavorCACertificates:     flavorCACertificates,
	}
}
