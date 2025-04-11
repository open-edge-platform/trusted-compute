/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package models

// CaCertTypes is an enumerated set of ca certificate types
type CaCertTypes string

const (
	CaCertTypesRootCa        CaCertTypes = "root"
	CaCertTypesEndorsementCa CaCertTypes = "endorsement"
	CaCertTypesEkCa          CaCertTypes = "ek" //endorsement is used instead to store cert
	CaCertTypesPrivacyCa     CaCertTypes = "privacy"
	CaCertTypesAikCa         CaCertTypes = "aik" //privacy is used instead to store cert
	CaCertTypesTagCa         CaCertTypes = "tag"
)

func (cct CaCertTypes) String() string {
	return string(cct)
}

// GetCaCertTypes returns a list of ca certificate types as strings
func GetCaCertTypes() []CaCertTypes {
	return []CaCertTypes{CaCertTypesRootCa,
		CaCertTypesEndorsementCa,
		CaCertTypesEkCa,
		CaCertTypesPrivacyCa,
		CaCertTypesAikCa,
		CaCertTypesTagCa}
}

// CaCertTypes is an enumerated set of certificate types
type CertTypes string

const (
	CertTypesSaml          CertTypes = "saml"
	CertTypesTls           CertTypes = "tls"
	CertTypesFlavorSigning CertTypes = "flavor-signing"
)

func (ct CertTypes) String() string {
	return string(ct)
}

func GetCertTypes() []CertTypes {
	return []CertTypes{CertTypesSaml, CertTypesTls}
}

// GetUniqueCertTypes returns a list of unique certificate types as strings
func GetUniqueCertTypes() []string {
	return []string{CaCertTypesRootCa.String(),
		CaCertTypesEndorsementCa.String(),
		CaCertTypesPrivacyCa.String(),
		CaCertTypesTagCa.String(),
		CertTypesSaml.String(),
		CertTypesTls.String(),
		CertTypesFlavorSigning.String()}
}

// GetUniqueCertTypes returns a list of unique certificate types as strings
func GetUniqueCertType(certType string) string {
	if certType == CaCertTypesEkCa.String() {
		return CaCertTypesEndorsementCa.String()
	}
	if certType == CaCertTypesAikCa.String() {
		return CaCertTypesPrivacyCa.String()
	}
	return certType
}

// Get list of certificate types including ca certificate types
func GetSupportedCerts() []string {
	var supportedCerts []string
	for _, c := range GetCaCertTypes() {
		supportedCerts = append(supportedCerts, c.String())
	}
	for _, c := range GetCertTypes() {
		supportedCerts = append(supportedCerts, c.String())
	}
	return supportedCerts
}

// Validate if certificate type is present in all certificate types including ca certificate types
func IsValidCertType(certType string) bool {
	for _, c := range GetSupportedCerts() {
		if c == certType {
			return true
		}
	}
	return false
}

// Validate if domain is present in specific certificate types
func IsValidDomainType(domain string) bool {
	return domain != "" &&
		(domain == CaCertTypesRootCa.String() ||
			domain == CaCertTypesEkCa.String() ||
			domain == CaCertTypesEndorsementCa.String() ||
			domain == CertTypesSaml.String())
}
