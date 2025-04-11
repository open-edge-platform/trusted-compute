/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net"
	"testing"
)

func getcsrbytes() *x509.CertificateRequest {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, constants.DefaultKeyAlgorithmLength)
	var extensions []pkix.Extension
	var oidExtensionBasicConstraints = []int{2, 5, 29, 19} //export from x509 package
	oidExtensionKeyUsage := []int{2, 5, 29, 15}
	bcExt := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true, Value: []byte{70, 128, 160, 70}}
	bcExt2 := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true, Value: []byte{70, 128, 160, 70}}
	extensions = append(extensions, bcExt)
	extensions = append(extensions, bcExt2)
	var csrTemplate = x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA384WithRSA,
		DNSNames:           []string{"10.10.10.10"},
		Subject: pkix.Name{
			CommonName: "AAS TLS Certificate",
		},
		ExtraExtensions: extensions,
	}
	buffer := new(bytes.Buffer)
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keyBytes)
	pem.Encode(buffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	payload, _ := ioutil.ReadAll(buffer)
	pemBlock, _ := pem.Decode(payload)
	clientCSR, _ := x509.ParseCertificateRequest(pemBlock.Bytes)
	return clientCSR
}

func TestValidateCertificateRequest(t *testing.T) {
	clientCSR := getcsrbytes()
	typeCert := "TLS"
	var role1 = ct.RoleInfo{"CMS", "CertApprover", "CN=AAS JWT Signing Certificate;CERTTYPE=JWT-Signing"}
	var role2 = ct.RoleInfo{"TLS", "CertApprover", "CN=AAS TLS Certificate;SAN=10.10.10.10,10.10.10.10;CERTTYPE=TLS"}
	var roles = map[string]ct.RoleInfo{role1.Context: role1, role2.Context: role2}
	conf, _ := config.Load()
	err := ValidateCertificateRequest(conf, clientCSR, typeCert, &roles)
	assert.NoError(t, err)
}

func TestValidateCertificateRequestInvalidRoles(t *testing.T) {
	clientCSR := getcsrbytes()
	typeCert := "TLS"
	var role1 = ct.RoleInfo{"CMS", "CertApprover", "CN=AAS JWT Signing Certificate;CERTTYPE=JWT-Signing"}
	var role2 = ct.RoleInfo{"TLS", "CertApprover", "CN=AAS TLS;SAN=10.10.10.10,10.10.10.10;CERTTYPE=TLS"}
	var roles = map[string]ct.RoleInfo{role1.Context: role1, role2.Context: role2}
	conf, _ := config.Load()
	err := ValidateCertificateRequest(conf, clientCSR, typeCert, &roles)
	assert.Error(t, err)
}

func TestValidateCertificateRequestMismatchIp(t *testing.T) {
	clientCSR := getcsrbytes()
	typeCert := "TLS"
	var role1 = ct.RoleInfo{"CMS", "CertApprover", "CN=AAS JWT Signing Certificate;CERTTYPE=JWT-Signing"}
	var role2 = ct.RoleInfo{"TLS", "CertApprover", "CN=AAS TLS Certificate;SAN=13.34.45.3,45.10.56.10;CERTTYPE=TLS"}
	var roles = map[string]ct.RoleInfo{role1.Context: role1, role2.Context: role2}
	conf, _ := config.Load()
	err := ValidateCertificateRequest(conf, clientCSR, typeCert, &roles)
	assert.Error(t, err)
}

func TestValidateCertificateRequestInvalidIp(t *testing.T) {
	ip := []net.IP{net.IPv4(8, 8, 8, 8)}
	value := ipInSlice("8.8.8.8", ip)
	assert.Equal(t, value, true)
}
