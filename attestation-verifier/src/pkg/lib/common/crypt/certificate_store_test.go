/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestLoadCertificates(t *testing.T) {
	type args struct {
		certificatePaths *CertificatesPathStore
		certType         []string
	}

	// Load certificates from pem file

	certsBytes, err := ioutil.ReadFile("test_data/cert/e36663d78.pem")
	if err != nil {
		log.WithError(err).Warn("Unable to read file")
	}

	var certificates []x509.Certificate
	block, _ := pem.Decode(certsBytes)
	if block == nil {
		log.WithError(err).Warn("Unable to decode pem bytes")
	}
	certAuth, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.WithError(err).Warn("crypt/x509:GetSubjectCertsMapFromPemFile() Failed to parse certificate")
	} else {
		certificates = append(certificates, *certAuth)
		log.Debugf("crypt/x509:GetSubjectCertsMapFromPemFile() CommonName %s", certAuth.Subject.CommonName)
	}

	// Load private key from pem file

	keyBytes, err := ioutil.ReadFile("test_data/key/key.pem")
	if err != nil {
		log.WithError(err).Warn("Unable to read file")
	}

	block, _ = pem.Decode(keyBytes)
	if block == nil || block.Type != "PKCS8 PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		log.WithError(err).Error("failed to parse private Key PEM file")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.WithError(err).Error("could not parse PKCS8 private key - err:", err)
	}

	tests := []struct {
		name string
		args args
		want *CertificatesStore
	}{
		{
			name: "Validate LoadCertificates with valid cert path",
			args: args{
				certificatePaths: &CertificatesPathStore{
					"root": CertLocation{
						KeyFile:  "test_data/key/key.pem",
						CertPath: "test_data/cert",
					},
					"test": CertLocation{
						KeyFile:  "test_data/key/key.pem",
						CertPath: "test_data/cert/e36663d78.pem",
					},
				},
				certType: []string{"root", "test"},
			},
			want: &CertificatesStore{
				"root": &CertificateStore{
					Key:          privKey,
					CertPath:     "test_data/cert",
					Certificates: certificates,
				},
				"test": &CertificateStore{
					Key:          privKey,
					CertPath:     "test_data/cert/e36663d78.pem",
					Certificates: certificates,
				},
			},
		},
		{
			name: "Validate LoadCertificates with empty key and cert file",
			args: args{
				certificatePaths: &CertificatesPathStore{
					"test": CertLocation{
						KeyFile:  "",
						CertPath: "",
					},
				},
				certType: []string{"test"},
			},
			want: &CertificatesStore{
				"test": &CertificateStore{},
			},
		},
		{
			name: "Validate LoadCertificates with invalid key and cert file",
			args: args{
				certificatePaths: &CertificatesPathStore{
					"test": CertLocation{
						KeyFile:  "test_data/invalid_cert.pem",
						CertPath: "test_data/invalid_cert.pem",
					},
				},
				certType: []string{"test"},
			},
			want: &CertificatesStore{
				"test": &CertificateStore{
					CertPath: "test_data/invalid_cert.pem",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := LoadCertificates(tt.args.certificatePaths, tt.args.certType); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadCertificates() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCertificatesStore_AddCertificatesToStore(t *testing.T) {
	type args struct {
		certType    string
		certFile    string
		certificate *x509.Certificate
	}
	tests := []struct {
		name    string
		cs      *CertificatesStore
		args    args
		wantErr bool
	}{
		{
			name: "Validate AddCertificatesToStore with valid cert path",
			cs: &CertificatesStore{
				"test": &CertificateStore{},
			},
			args: args{
				certType:    "test",
				certFile:    "test",
				certificate: &x509.Certificate{},
			},
			wantErr: false,
		},
		{
			name: "Validate AddCertificatesToStore with invalid cert path",
			cs: &CertificatesStore{
				"test": &CertificateStore{},
			},
			args: args{
				certType:    "test",
				certFile:    "test/\\",
				certificate: &x509.Certificate{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cs.AddCertificatesToStore(tt.args.certType, tt.args.certFile, tt.args.certificate); (err != nil) != tt.wantErr {
				t.Errorf("CertificatesStore.AddCertificatesToStore() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// Clean up
	os.Remove("test.pem")
}

func TestCertificatesStore_GetKeyAndCertificates(t *testing.T) {
	type args struct {
		certType string
	}
	tests := []struct {
		name    string
		cs      *CertificatesStore
		args    args
		want    crypto.PrivateKey
		want1   []x509.Certificate
		wantErr bool
	}{
		{
			name: "Validate GetKeyAndCertificates with valid cert path",
			cs: &CertificatesStore{
				"test": &CertificateStore{},
			},
			args: args{
				certType: "test",
			},
			want:    nil,
			want1:   nil,
			wantErr: false,
		},
		{
			name: "Validate GetKeyAndCertificates with invalid cert path",
			cs:   &CertificatesStore{},
			args: args{
				certType: "test",
			},
			want:    nil,
			want1:   nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tt.cs.GetKeyAndCertificates(tt.args.certType)
			if (err != nil) != tt.wantErr {
				t.Errorf("CertificatesStore.GetKeyAndCertificates() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificatesStore.GetKeyAndCertificates() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("CertificatesStore.GetKeyAndCertificates() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

func TestCertificatesStore_RetrieveCertificate(t *testing.T) {
	type args struct {
		certType   string
		commonName string
	}
	tests := []struct {
		name    string
		cs      *CertificatesStore
		args    args
		want    *x509.Certificate
		wantErr bool
	}{
		{
			name: "Validate RetrieveCertificate with empty output cert",
			cs: &CertificatesStore{
				"test": &CertificateStore{},
			},
			args: args{
				certType: "test",
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "Validate RetrieveCertificate with filled output cert",
			cs: &CertificatesStore{
				"test": &CertificateStore{
					Certificates: []x509.Certificate{
						x509.Certificate{},
					},
				},
			},
			args: args{
				certType: "test",
			},
			want:    &x509.Certificate{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cs.RetrieveCertificate(tt.args.certType, tt.args.commonName)
			if (err != nil) != tt.wantErr {
				t.Errorf("CertificatesStore.RetrieveCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CertificatesStore.RetrieveCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
