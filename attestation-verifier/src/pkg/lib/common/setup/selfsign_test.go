/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"crypto"
	"crypto/x509"
	"io"
	"os"
	"testing"
)

func TestSign(t *testing.T) {
	testSign := SelfSignedCert{
		KeyFile:  "test.pem",
		CertFile: "test.crt",
	}
	if err := testSign.Run(); err != nil {
		t.Error("Failed to generate self-signed key and cert", err.Error())
	}
	if err := testSign.Validate(); err != nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// Error case - Cert file does not exist
	testSignError := SelfSignedCert{
		KeyFile:  "test.pem",
		CertFile: "test_error.crt",
	}

	if err := testSignError.Validate(); err == nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// Error case - Key file does not exist
	testSignError = SelfSignedCert{
		KeyFile:  "test_error.pem",
		CertFile: "test.crt",
	}

	if err := testSignError.Validate(); err == nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// Error case - key file not provided
	testSignError = SelfSignedCert{
		CertFile: "test.crt",
	}

	if err := testSignError.Run(); err == nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// Error case - cert file not provided
	testSignError = SelfSignedCert{
		KeyFile: "test.crt",
	}

	if err := testSignError.Run(); err == nil {
		t.Error("Failed to validate self-signed key and cert", err.Error())
	}

	// cleanup
	_ = os.Remove("test.pem")
	_ = os.Remove("test.crt")

}

func TestSelfSignedCert_SetName(t *testing.T) {
	type fields struct {
		KeyFile       string
		CertFile      string
		CommonName    string
		SANList       string
		Issuer        string
		ValidityDays  int
		PublicKey     crypto.PublicKey
		PrivateKey    crypto.PrivateKey
		ConsoleWriter io.Writer
		template      *x509.Certificate
		selfSignCert  []byte
		commandName   string
		envPrefix     string
	}
	type args struct {
		n string
		e string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Validate self sign certificate",
			args: args{
				n: "test",
				e: "test",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &SelfSignedCert{
				KeyFile:       tt.fields.KeyFile,
				CertFile:      tt.fields.CertFile,
				CommonName:    tt.fields.CommonName,
				SANList:       tt.fields.SANList,
				Issuer:        tt.fields.Issuer,
				ValidityDays:  tt.fields.ValidityDays,
				PublicKey:     tt.fields.PublicKey,
				PrivateKey:    tt.fields.PrivateKey,
				ConsoleWriter: tt.fields.ConsoleWriter,
				template:      tt.fields.template,
				selfSignCert:  tt.fields.selfSignCert,
				commandName:   tt.fields.commandName,
				envPrefix:     tt.fields.envPrefix,
			}
			tr.SetName(tt.args.n, tt.args.e)
		})
	}
}
