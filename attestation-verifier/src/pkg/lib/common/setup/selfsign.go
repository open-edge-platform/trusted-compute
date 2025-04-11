/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/pkg/errors"
)

const defaultRSAKeylength = 3072
const defaultIssuer = "intel"
const defaultValidityDays = 365

const selfSignEnvHelpPrompt = "Following environment variables are optionally used in "

var selfSignEnvHelp = map[string]string{
	"CERT_FILE":      "The file to which certificate is saved",
	"KEY_FILE":       "The file to which private key is saved",
	"COMMON_NAME":    "The common name of signed certificate",
	"ISSUER":         "The issuer of signed certificate",
	"VALIDITY_YEARS": "The validity time in years of signed certificate",
}

type SelfSignedCert struct {
	KeyFile  string
	CertFile string

	CommonName string
	SANList    string
	Issuer     string
	// this actually means years
	ValidityDays int

	PublicKey     crypto.PublicKey
	PrivateKey    crypto.PrivateKey
	ConsoleWriter io.Writer

	template     *x509.Certificate
	selfSignCert []byte
	commandName  string
	envPrefix    string
}

func (t *SelfSignedCert) Validate() error {
	_, err := os.Stat(t.CertFile)
	if os.IsNotExist(err) {
		return errors.New("Can not find certificate at: " + t.CertFile)
	} else if err != nil {
		return errors.Wrap(err, "Can not access certificate file: "+t.CertFile)
	}
	_, err = os.Stat(t.KeyFile)
	if os.IsNotExist(err) {
		return errors.New("Can not find private key at: " + t.KeyFile)
	} else if err != nil {
		return errors.Wrap(err, "Can not access private key file: "+t.CertFile)
	}
	return nil
}

func (t *SelfSignedCert) Run() error {
	var err error
	if err = t.testArgs(); err != nil {
		return err
	}
	printToWriter(t.ConsoleWriter, t.commandName, "Creating self-signed certificate at path: "+t.CertFile)
	// generate key pair if not set
	if t.PrivateKey == nil ||
		t.PublicKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, defaultRSAKeylength)
		if err != nil {
			return errors.Wrap(err, "Failed to generate RSA private key")
		}
		t.PrivateKey = key
		t.PublicKey = &key.PublicKey
	}
	// generate template
	t.template = &x509.Certificate{
		Subject: pkix.Name{
			CommonName: t.CommonName,
		},
		Issuer: pkix.Name{
			CommonName: t.Issuer,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(t.ValidityDays, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// split san list
	hosts := strings.Split(t.SANList, ",")
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			t.template.IPAddresses = append(t.template.IPAddresses, ip)
		} else {
			t.template.DNSNames = append(t.template.DNSNames, h)
		}
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return errors.Wrap(err, "Failed to create serial number")
	}
	t.template.SerialNumber = serialNumber

	// sign the certificate with key
	if err = t.sign(); err != nil {
		return err
	}
	// store key and cert to file
	keyDer, err := x509.MarshalPKCS8PrivateKey(t.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "Failed to marshal private key")
	}
	if err = crypt.SavePrivateKeyAsPKCS8(keyDer, t.KeyFile); err != nil {
		return errors.Wrap(err, "Failed to save private key to file")
	}
	if err = crypt.SavePemCert(t.selfSignCert, t.CertFile); err != nil {
		return errors.Wrap(err, "Failed to save certificate to file")
	}
	printToWriter(t.ConsoleWriter, t.commandName, "Self-signed certificate created at path: "+t.CertFile)
	return nil
}

// nothing to print for this task
func (t *SelfSignedCert) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, selfSignEnvHelpPrompt+t.commandName, t.envPrefix, selfSignEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *SelfSignedCert) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = PrefixUnderscroll(e)
}

func (t *SelfSignedCert) testArgs() error {
	if t.CertFile == "" {
		return errors.New("SelfSignedCert Failed: Invalid path to certificate")
	}
	if t.KeyFile == "" {
		return errors.New("SelfSignedCert Failed: Invalid path to private key")
	}
	if t.Issuer == "" {
		t.Issuer = defaultIssuer
	}
	if t.ValidityDays <= 0 {
		t.ValidityDays = defaultValidityDays
	}
	return nil
}

func (t *SelfSignedCert) sign() error {
	var err error
	if t.PrivateKey == nil ||
		t.PublicKey == nil ||
		t.template == nil {
		return errors.New("Failed to create self signed certificate: invalid configuration")
	}
	t.selfSignCert, err = x509.CreateCertificate(rand.Reader, t.template, t.template, t.PublicKey, t.PrivateKey)
	if err != nil {
		return errors.Wrap(err, "x509.CreateCertificate Failed")
	}
	return nil
}
