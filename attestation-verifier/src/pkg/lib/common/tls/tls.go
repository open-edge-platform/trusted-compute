/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tls

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
)

// VerifyCertBySha256 method is used to verify the host certificate with tls SHA256 fingerprint
func VerifyCertBySha256(certSha256 [32]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) <= 0 {
			return errors.New("Client tls: no certificates supplied")
		}
		hostRawCert := rawCerts[0]
		fingerprint := sha256.Sum256(hostRawCert)
		if fingerprint != certSha256 {
			return errors.New("Client tls: fingerprint does not match")
		}
		return verifyByHostCert(hostRawCert, rawCerts)
	}
}

// VerifyCertBySha384 method is used to verify the host certificate with tls SHA384 fingerprint
func VerifyCertBySha384(certSha384 [48]byte) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) <= 0 {
			return errors.New("Client tls: no certificates supplied")
		}
		hostRawCert := rawCerts[0]
		fingerprint := sha512.Sum384(hostRawCert)
		if fingerprint != certSha384 {
			return errors.New("Client tls: fingerprint does not match")
		}
		return verifyByHostCert(hostRawCert, rawCerts)
	}
}

func verifyByHostCert(hostRawCert []byte, rawCerts [][]byte) error {
	hostCert, err := x509.ParseCertificate(hostRawCert)
	if err != nil {
		return errors.New("Client tls: could not parse certificate")
	}
	intermediates := x509.NewCertPool()
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(rawCerts) == 1 || hostCert.IsCA {
		roots.AddCert(hostCert)
	}
	rest := rawCerts[1:]
	for _, rawCert := range rest {
		cert, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return errors.New("Client tls: failed to parse x509 certificate")
		}
		if cert.IsCA {
			roots.AddCert(cert)
		} else {
			intermediates.AddCert(cert)
		}
	}
	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}
	_, err = hostCert.Verify(opts)
	return err
}
