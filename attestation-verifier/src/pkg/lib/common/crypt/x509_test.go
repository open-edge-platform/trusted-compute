/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/crl"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestVerifyX509CertChainGoodChain(t *testing.T) {
	rootCAPkixName := pkix.Name{
		CommonName:    "Acme Corp Signing Root CA",
		Organization:  []string{"Acme"},
		Country:       []string{"US"},
		Province:      []string{"CA"},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"123 Anony Mouse Blvd."},
		PostalCode:    []string{"12345"},
	}

	intermediate1PkixName := pkix.Name{
		CommonName: "Acme TPM Intermediate CA",
	}

	ekCertPkixName := pkix.Name{
		CommonName: "Acme TPM EK Cert",
	}

	// Generate a self signed root CA
	caPrivateKey, caPubkey, _ := GenerateKeyPair("rsa", 4096)

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               rootCAPkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create intermediate Certs for signing the leaf
	intermediateCert1Template := x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               intermediate1PkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create the chain starting with Root
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, &rootCaTemplate, &rootCaTemplate,
		caPubkey, caPrivateKey)
	rootCertx509, err := x509.ParseCertificate(rootCertBytes)

	// INTER 1
	intermediate1CertBytes, err := x509.CreateCertificate(rand.Reader, &intermediateCert1Template, rootCertx509,
		caPubkey, caPrivateKey)
	intermediate1Certx509, err := x509.ParseCertificate(intermediate1CertBytes)

	// LEAF
	ekCertTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2023),
		Subject:      ekCertPkixName,
		NotBefore:    time.Now().AddDate(-2, 0, 0),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageEncipherOnly,
	}

	// create the EK leaf certificate
	ekCertificateBytes, err := x509.CreateCertificate(rand.Reader, &ekCertTemplate, intermediate1Certx509,
		caPubkey, caPrivateKey)
	t.Log(err)

	ekCertx509, err := x509.ParseCertificate(ekCertificateBytes)

	// since go packages cannot handle this extension, this field will be set
	extKeyUsage := asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	ekCertx509.UnknownExtKeyUsage = append(ekCertx509.UnknownExtKeyUsage, extKeyUsage)

	t.Log(err)

	// combine all certs
	var allCerts []*x509.Certificate
	allCerts = append(allCerts, rootCertx509, intermediate1Certx509, ekCertx509)

	assert.NoError(t, VerifyEKCertChain(false, allCerts, nil))
	assert.NoError(t, VerifyEKCertChain(false, []*x509.Certificate{ekCertx509}, GetCertPool(append([]x509.Certificate{}, *rootCertx509, *intermediate1Certx509))))
}

func TestVerifyX509CertChainExpired(t *testing.T) {
	rootCAPkixName := pkix.Name{
		CommonName:    "Acme Corp Signing Root CA",
		Organization:  []string{"Acme"},
		Country:       []string{"US"},
		Province:      []string{"CA"},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"123 Anony Mouse Blvd."},
		PostalCode:    []string{"12345"},
	}

	intermediate1PkixName := pkix.Name{
		CommonName: "Acme TPM Model CA",
	}

	ekCertPkixName := pkix.Name{
		CommonName: "Acme TPM EK Cert",
	}

	// Generate a self signed root CA
	caPrivateKey, caPubkey, err := GenerateKeyPair("rsa", 4096)

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               rootCAPkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create intermediate Certs for signing the leaf
	intermediateCert1Template := x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               intermediate1PkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the chain starting with Root
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, &rootCaTemplate, &rootCaTemplate, caPubkey, caPrivateKey)
	rootCertx509, err := x509.ParseCertificate(rootCertBytes)

	// INTER 1
	intermediate1CertBytes, err := x509.CreateCertificate(rand.Reader, &intermediateCert1Template, rootCertx509,
		rootCertx509.PublicKey, caPrivateKey)
	intermediate1Certx509, err := x509.ParseCertificate(intermediate1CertBytes)

	leafPrivKey, leafPubKey, err := GenerateKeyPair("rsa", 4096)

	// LEAF
	ekCertTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2023),
		Subject:               ekCertPkixName,
		NotBefore:             time.Now().AddDate(-2, 0, 0),
		NotAfter:              time.Now().AddDate(-1, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		KeyUsage:              x509.KeyUsageEncipherOnly,
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		DNSNames:              []string{"test.example.com"},
		EmailAddresses:        []string{"somebody@thatiusedtoknow.org"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: []byte("extra extension"),
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	// create the EK leaf certificate
	ekCertificateBytes, err := x509.CreateCertificate(rand.Reader, &ekCertTemplate, &intermediateCert1Template,
		leafPubKey, leafPrivKey)

	ekCertx509, err := x509.ParseCertificate(ekCertificateBytes)
	t.Log(err)
	// since go packages cannot handle this extension, this field will be set
	extKeyUsage := asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	ekCertx509.UnknownExtKeyUsage = append(ekCertx509.UnknownExtKeyUsage, extKeyUsage)
	ekCertx509.UnknownExtKeyUsage = nil

	// combine all certs
	var allCerts []*x509.Certificate
	allCerts = append(allCerts, rootCertx509, intermediate1Certx509, ekCertx509)

	assert.Error(t, VerifyEKCertChain(false, allCerts, nil))
	assert.Error(t, VerifyEKCertChain(false, []*x509.Certificate{ekCertx509}, GetCertPool(append([]x509.Certificate{}, *rootCertx509, *intermediate1Certx509))))

	// unset the EK cert usage
	ekCertx509.UnknownExtKeyUsage = nil
	assert.Error(t, VerifyEKCertChain(false, []*x509.Certificate{ekCertx509}, GetCertPool(append([]x509.Certificate{}, *rootCertx509, *intermediate1Certx509))))
}

func TestEmptyX509Verify(t *testing.T) {
	rootCAPkixName := pkix.Name{
		CommonName:    "Acme Corp Signing Root CA",
		Organization:  []string{"Acme"},
		Country:       []string{"US"},
		Province:      []string{"CA"},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"123 Anony Mouse Blvd."},
		PostalCode:    []string{"12345"},
	}

	intermediate1PkixName := pkix.Name{
		CommonName: "Acme TPM Model CA",
	}

	// Generate a self signed root CA
	caPrivateKey, caPubkey, _ := GenerateKeyPair("rsa", 4096)

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               rootCAPkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create intermediate Certs for signing the leaf
	intermediateCert1Template := x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               intermediate1PkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the chain starting with Root
	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, &rootCaTemplate, &rootCaTemplate, caPubkey, caPrivateKey)
	rootCertx509, _ := x509.ParseCertificate(rootCertBytes)

	// INTER 1
	intermediate1CertBytes, _ := x509.CreateCertificate(rand.Reader, &intermediateCert1Template, rootCertx509,
		rootCertx509.PublicKey, caPrivateKey)
	intermediate1Certx509, _ := x509.ParseCertificate(intermediate1CertBytes)

	// combine all certs
	var allCerts []*x509.Certificate
	allCerts = append(allCerts, rootCertx509, intermediate1Certx509)

	assert.Error(t, VerifyEKCertChain(false, allCerts, nil))
}

func TestRevokedX509(t *testing.T) {
	var revCrlBytes []byte

	rootCAPkixName := pkix.Name{
		CommonName:    "Acme Corp Signing Root CA",
		Organization:  []string{"Acme"},
		Country:       []string{"US"},
		Province:      []string{"CA"},
		Locality:      []string{"Santa Clara"},
		StreetAddress: []string{"123 Anony Mouse Blvd."},
		PostalCode:    []string{"12345"},
	}

	intermediate1PkixName := pkix.Name{
		CommonName: "Acme TPM Model CA",
	}

	ekCertPkixName := pkix.Name{
		CommonName: "Acme TPM EK Cert",
	}

	// Generate a self signed root CA
	caPrivateKey, caPubkey, _ := GenerateKeyPair("rsa", 4096)

	rootCaTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2020),
		Subject:               rootCAPkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create the chain starting with Root
	rootCertBytes, _ := x509.CreateCertificate(rand.Reader, &rootCaTemplate, &rootCaTemplate, caPubkey, caPrivateKey)
	rootCertx509, _ := x509.ParseCertificate(rootCertBytes)

	// setup router for CRL Distribution point
	r := mux.NewRouter()

	r.HandleFunc("/rootca.crl", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(revCrlBytes)
		if err != nil {
			t.Log("test/test_utility:mockServer(): Unable to write data")
		}
	}).Methods(http.MethodGet)

	// Create intermediate Certs for signing the leaf
	intermediateCert1Template := x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               intermediate1PkixName,
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		CRLDistributionPoints: []string{"http://rootca.crl"},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// INTER 1
	intermediate1CertBytes, _ := x509.CreateCertificate(rand.Reader, &intermediateCert1Template, rootCertx509,
		rootCertx509.PublicKey, caPrivateKey)
	intermediate1Certx509, _ := x509.ParseCertificate(intermediate1CertBytes)

	revokeCerts := []pkix.RevokedCertificate{
		{
			SerialNumber:   intermediate1Certx509.SerialNumber,
			RevocationTime: time.Now(),
		},
	}

	revCrlBytes, _ = crl.CreateGenericCRL(revokeCerts, caPrivateKey.(crypto.Signer), rootCertx509, time.Now().AddDate(1, 0, 0))

	// LEAF
	ekCertTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2023),
		Subject:               ekCertPkixName,
		NotBefore:             time.Now().AddDate(-2, 0, 0),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		KeyUsage:              x509.KeyUsageEncipherOnly,
		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},
		DNSNames:              []string{"test.example.com"},
		EmailAddresses:        []string{"somebody@thatiusedtoknow.org"},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: []byte("extra extension"),
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}

	// create the EK leaf certificate
	ekCertificateBytes, _ := x509.CreateCertificate(rand.Reader, &ekCertTemplate, intermediate1Certx509,
		caPubkey, caPrivateKey)

	ekCertx509, _ := x509.ParseCertificate(ekCertificateBytes)

	// since go packages cannot handle this extension, this field will be set
	extKeyUsage := asn1.ObjectIdentifier{2, 23, 133, 8, 1}
	ekCertx509.UnknownExtKeyUsage = append(ekCertx509.UnknownExtKeyUsage, extKeyUsage)

	// combine all certs
	var allCerts []*x509.Certificate
	allCerts = append(allCerts, rootCertx509, intermediate1Certx509, ekCertx509)

	// With  revocation checks turned on - the verification will fail
	assert.Error(t, VerifyEKCertChain(true, allCerts, GetCertPool(append([]x509.Certificate{}, *rootCertx509, *intermediate1Certx509))))

	// Without revocation checks - this will continue to pass
	assert.NoError(t, VerifyEKCertChain(false, allCerts, GetCertPool(append([]x509.Certificate{}, *rootCertx509, *intermediate1Certx509))))
}

func TestGenerateKeyPair(t *testing.T) {
	type args struct {
		keyType   string
		keyLength int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Generate rsa key",
			args: args{
				keyType: "rsa",
			},
			wantErr: false,
		},
		{
			name: "Generate ecdsa key - keylength less than 521",
			args: args{
				keyType: "ecdsa",
			},
			wantErr: false,
		},
		{
			name: "Generate ecdsa key - keylength greater than or equal to 521",
			args: args{
				keyType:   "ecdsa",
				keyLength: 521,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := GenerateKeyPair(tt.args.keyType, tt.args.keyLength)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetSignatureAlgorithm(t *testing.T) {
	type args struct {
		pubKey crypto.PublicKey
	}
	tests := []struct {
		name    string
		args    args
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{
			name: "Get signature algorithm for rsa public key",
			args: args{
				pubKey: &rsa.PublicKey{},
			},
			want:    x509.SHA384WithRSA,
			wantErr: false,
		},
		{
			name: "Get signature algorithm for ecdsa - 256  public key",
			args: args{
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P256(),
				},
			},
			want:    x509.ECDSAWithSHA256,
			wantErr: false,
		},
		{
			name: "Get signature algorithm for ecdsa - 384  public key",
			args: args{
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P384(),
				},
			},
			want:    x509.ECDSAWithSHA384,
			wantErr: false,
		},
		{
			name: "Get signature algorithm for ecdsa - 521  public key",
			args: args{
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P521(),
				},
			},
			want:    x509.ECDSAWithSHA512,
			wantErr: false,
		},
		{
			name: "Get signature algorithm for ecdsa - invalid  public key",
			args: args{
				pubKey: &ecdsa.PublicKey{
					Curve: elliptic.P224(),
				},
			},
			want:    x509.UnknownSignatureAlgorithm,
			wantErr: true,
		},
		{
			name: "Get signature algorithm for unknown algorithm",
			args: args{
				pubKey: &dsa.PublicKey{},
			},
			want:    x509.UnknownSignatureAlgorithm,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetSignatureAlgorithm(tt.args.pubKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetSignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateKeyPairAndCertificateRequest(t *testing.T) {
	type args struct {
		subject   pkix.Name
		hostList  string
		keyType   string
		keyLength int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Create new key pair certificate request",
			args: args{
				subject: pkix.Name{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := CreateKeyPairAndCertificateRequest(tt.args.subject, tt.args.hostList, tt.args.keyType, tt.args.keyLength)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKeyPairAndCertificateRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestCreateKeyPairAndCertificate(t *testing.T) {
	type args struct {
		subject   string
		hostList  string
		keyType   string
		keyLength int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Create new key pair certificate",
			args: args{
				subject:  "test",
				hostList: "test",
				keyType:  "rsa",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := CreateKeyPairAndCertificate(tt.args.subject, tt.args.hostList, tt.args.keyType, tt.args.keyLength)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateKeyPairAndCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetPublicKeyFromCert(t *testing.T) {
	type args struct {
		cert *x509.Certificate
	}
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			name: "Get RSA public key from cert",
			args: args{
				cert: &x509.Certificate{
					PublicKeyAlgorithm: x509.RSA,
					PublicKey:          &rsa.PublicKey{},
				},
			},
			want:    &rsa.PublicKey{},
			wantErr: false,
		},
		{
			name: "Invalid RSA public key in cert",
			args: args{
				cert: &x509.Certificate{
					PublicKeyAlgorithm: x509.RSA,
					PublicKey:          &ecdsa.PublicKey{},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Get ECDSA public key from cert",
			args: args{
				cert: &x509.Certificate{
					PublicKeyAlgorithm: x509.ECDSA,
					PublicKey:          &ecdsa.PublicKey{},
				},
			},
			want:    &ecdsa.PublicKey{},
			wantErr: false,
		},
		{
			name: "Invalid ECDSA public key in cert",
			args: args{
				cert: &x509.Certificate{
					PublicKeyAlgorithm: x509.ECDSA,
					PublicKey:          &rsa.PublicKey{},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Invalid certificate",
			args: args{
				cert: &x509.Certificate{
					PublicKey: &rsa.PublicKey{},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPublicKeyFromCert(tt.args.cert)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKeyFromCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPublicKeyFromCert() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPublicKeyFromCertPem(t *testing.T) {
	type args struct {
		certPem []byte
	}
	derBytes, privKeyBytes, err := CreateKeyPairAndCertificate("test", "test", "rsa", 3072)
	if err != nil {
		log.Error("Error in creating key pair and certificate")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			name: "Validate GetPublicKeyFromCertPem with valid cert",
			args: args{
				certPem: cert,
			},
			want:    &privKey.(*rsa.PrivateKey).PublicKey,
			wantErr: false,
		},
		{
			name: "Validate GetPublicKeyFromCertPem with invalid cert",
			args: args{
				certPem: nil,
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPublicKeyFromCertPem(tt.args.certPem)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKeyFromCertPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPublicKeyFromCertPem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPrivateKeyFromPem(t *testing.T) {
	type args struct {
		keyPem []byte
	}
	certBytes, privKeyBytes, err := CreateKeyPairAndCertificate("test", "test", "rsa", 3072)
	if err != nil {
		log.Error("Error in creating key pair and certificate")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		log.Error("Error in parsing private key")
	}
	privKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	invalidPrivKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: certBytes})
	tests := []struct {
		name    string
		args    args
		want    crypto.PrivateKey
		wantErr bool
	}{
		{
			name: "GetPrivateKeyFromPem with valid cert",
			args: args{
				keyPem: privKeyPem,
			},
			want:    privKey,
			wantErr: false,
		},
		{
			name: "GetPrivateKeyFromPem with invalid output",
			args: args{
				keyPem: privKeyBytes,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "GetPrivateKeyFromPem with invalid cert",
			args: args{
				keyPem: invalidPrivKeyPem,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPrivateKeyFromPem(tt.args.keyPem)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrivateKeyFromPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPrivateKeyFromPem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetPublicKeyFromPem(t *testing.T) {
	type args struct {
		keyPem []byte
	}
	certBytes, privKeyBytes, err := CreateKeyPairAndCertificate("test", "test", "rsa", 3072)
	if err != nil {
		log.Error("Error in creating key pair and certificate")
	}
	privKey, err := x509.ParsePKCS8PrivateKey(privKeyBytes)
	if err != nil {
		log.Error("Error in parsing private key")
	}
	publicKey := privKey.(*rsa.PrivateKey).PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		log.Error("Error in marshalling public key")
	}
	publicKeyPem := pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: publicKeyBytes,
	})
	invalidPublicKeyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: certBytes})
	tests := []struct {
		name    string
		args    args
		want    crypto.PublicKey
		wantErr bool
	}{
		{
			name: "GetPublicKeyFromPem with valid data",
			args: args{
				keyPem: publicKeyPem,
			},
			want:    &publicKey,
			wantErr: false,
		},
		{
			name: "GetPublicKeyFromPem with invalid output",
			args: args{
				keyPem: privKeyBytes,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "GetPublicKeyFromPem with invalid cert",
			args: args{
				keyPem: invalidPublicKeyPem,
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetPublicKeyFromPem(tt.args.keyPem)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPublicKeyFromPem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetPublicKeyFromPem() = %v, want %v", got, tt.want)
			}
		})
	}
}
