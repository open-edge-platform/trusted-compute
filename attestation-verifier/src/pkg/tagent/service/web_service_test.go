/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
)

const (
	privacyCA  = "../test/resources/service-privacy-ca.pem"
	testLogDir = "../test/resources/var/log/"
)

func createCertificate() {
	ca := &x509.Certificate{
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
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		log.Fatalf("Failed to CreateCertificate %v", err)
	}
	caPEMFile, err := os.OpenFile(privacyCA, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
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
		log.Fatalf("Error writing certificate file" + err.Error())
	}
	return
}

func TestTrustAgentWebServiceStart(t *testing.T) {
	os.MkdirAll(testLogDir, os.ModePerm)
	createCertificate()
	type fields struct {
		webParameters WebParameters
		router        *mux.Router
		server        *http.Server
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate Start trustAgentWebService",
			fields: fields{
				webParameters: WebParameters{
					ServerConfig: config.ServerConfig{
						Port:        8000,
						ReadTimeout: time.Duration(time.Hour),
					},
					TLSCertFilePath:           privacyCA,
					TLSKeyFilePath:            "../test/mockWebCACertsDir/681de0eca.pem",
					TrustedJWTSigningCertsDir: "../test/mockWebCACertsDir/",
					TrustedCaCertsDir:         "../test/mockWebCACertsDir/",
				},
				router: mux.NewRouter(),
				server: &http.Server{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &trustAgentWebService{
				webParameters: tt.fields.webParameters,
				router:        tt.fields.router,
				server:        tt.fields.server,
				httpLogFile:   filepath.Join(testLogDir, "httplog.log"),
			}
			service.Start()
		})
	}
}

func TestTrustAgentWebServiceStop(t *testing.T) {
	defer func() {
		os.RemoveAll(testLogDir)
	}()
	type fields struct {
		webParameters WebParameters
		router        *mux.Router
		server        *http.Server
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate Stop trustAgentWebService",
			fields: fields{
				webParameters: WebParameters{
					ServerConfig: config.ServerConfig{
						Port:        8000,
						ReadTimeout: time.Duration(time.Hour),
					},
					TLSCertFilePath:           "",
					TLSKeyFilePath:            "",
					TrustedJWTSigningCertsDir: "",
					TrustedCaCertsDir:         "",
				},
				router: mux.NewRouter(),
				server: &http.Server{},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &trustAgentWebService{
				webParameters: tt.fields.webParameters,
				router:        tt.fields.router,
				server:        tt.fields.server,
			}
			if err := service.Stop(); (err != nil) != tt.wantErr {
				t.Errorf("trustAgentWebService.Stop() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
