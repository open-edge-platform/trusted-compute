/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"testing"
	"time"
)

const (
	privacyCALocation = "../test/resources/privacy-ca.cer"
	invalidCALocation = "../test/resources/testcert.cer"
)

func createTestResource() {
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"TEST, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatalf("Failed to generate KeyPair %v", err)
	}

	// save certificate
	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}
	caPEMFile, err := os.OpenFile(privacyCALocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := caPEMFile.Close()
		if derr != nil {
			log.Fatalf("Error while closing file" + derr.Error())
		}
	}()
	_, err = caPEMFile.Write(caBytes)
	if err != nil {
		log.Fatalf("Failed to write Certificate %v", err)
	}

	// Create test.cer file
	testPEMFile, err := os.OpenFile(invalidCALocation, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("I/O error while saving private key file %v", err)
	}
	defer func() {
		derr := testPEMFile.Close()
		if derr != nil {
			log.Fatalf("Error while closing file" + derr.Error())
		}
	}()
	err = pem.Encode(testPEMFile, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	if err != nil {
		log.Fatalf("Failed to Encode Certificate %v", err)
	}

	return
}

func TestGetPrivacyCA(t *testing.T) {
	createTestResource()
	defer func() {
		err := os.Remove(privacyCALocation)
		assert.NoError(t, err)
		err = os.Remove(invalidCALocation)
		assert.NoError(t, err)
	}()
	type args struct {
		privacyCA string
	}
	tests := []struct {
		name    string
		args    args
		want    *rsa.PublicKey
		wantErr bool
	}{
		{
			name: "Invalid case invalid file",
			args: args{
				privacyCA: invalidCALocation,
			},
			wantErr: true,
		},
		{
			name: "Invalid case empty file location",
			args: args{
				privacyCA: "",
			},
			wantErr: true,
		},
		{
			name: "Valid case",
			args: args{
				privacyCA: privacyCALocation,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GetPrivacyCA(tt.args.privacyCA)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPrivacyCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
