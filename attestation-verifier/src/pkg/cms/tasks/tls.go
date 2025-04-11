/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"
)

// Should move this to lib common, as it is duplicated across CMS and TDA
type TLS struct {
	ConsoleWriter    io.Writer
	TLSCertDigestPtr *string
	TLSSanList       string
	envPrefix        string
	commandName      string
	TLSKeyPath       string
	TLSCertPath      string
	SerialNumberPath string
	CaAttribs        map[string]constants.CaAttrib
}

const tlsEnvHelpPrompt = "Following environment variables are required for tls setup:"

var tlsEnvHelp = map[string]string{
	"SAN_LIST": "TLS SAN list",
}

func outboundHost() (string, error) {
	log.Trace("tasks/tls:outboundHost() Entering")
	defer log.Trace("tasks/tls:outboundHost() Leaving")

	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return os.Hostname()
	}
	defer func() {
		derr := conn.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing connection")
		}
	}()

	return (conn.LocalAddr().(*net.UDPAddr)).IP.String(), nil
}

func (ts TLS) createTLSCert(hosts string, ca *x509.Certificate, caKey interface{}) (key []byte, cert []byte, err error) {
	log.Trace("tasks/tls:createTLSCert() Entering")
	defer log.Trace("tasks/tls:createTLSCert() Leaving")

	csrData, key, err := crypt.CreateKeyPairAndCertificateRequest(pkix.Name{
		Country:      []string{constants.DefaultCountry},
		Organization: []string{constants.DefaultOrganization},
		Locality:     []string{constants.DefaultLocality},
		Province:     []string{constants.DefaultProvince},
		CommonName:   "CMS",
	}, hosts, constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not create CSR")
	}

	clientCSR, err := x509.ParseCertificateRequest(csrData)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not parse CSR")
	}

	serialNumber, err := utils.GetNextSerialNumber(ts.SerialNumberPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could get next serial number")
	}

	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		IPAddresses: clientCSR.IPAddresses,
		DNSNames:    clientCSR.DNSNames,

		SerialNumber: serialNumber,
		Issuer:       ca.Issuer,
		Subject:      clientCSR.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageContentCommitment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	cert, err = x509.CreateCertificate(rand.Reader, &clientCRTTemplate, ca, clientCSR.PublicKey, caKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/tls:createTLSCert() Could not create certificate")
	}
	return
}

func (ts TLS) Run() error {
	log.Trace("tasks/tls:Run() Entering")
	defer log.Trace("tasks/tls:Run() Leaving")

	fmt.Fprintln(ts.ConsoleWriter, "Running tls setup...")

	hosts := strings.Split(ts.TLSSanList, ",")

	// validate host names
	for _, h := range hosts {
		validErr := validation.ValidateHostname(h)
		if validErr != nil {
			return errors.Wrap(validErr, "tasks/tls:Run() Host name is not valid")
		}
	}

	tlsCaAttr := constants.GetCaAttribs(constants.Tls, ts.CaAttribs)
	tlsCaCert, tlsCaPrivKey, err := crypt.LoadX509CertAndPrivateKey(tlsCaAttr.CertPath, tlsCaAttr.KeyPath)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Could not load cert and private key")
	}
	key, cert, err := ts.createTLSCert(ts.TLSSanList, tlsCaCert, tlsCaPrivKey)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Could not create TLS certificate")
	}
	err = crypt.SavePrivateKeyAsPKCS8(key, ts.TLSKeyPath)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Could not save TLS private key")
	}
	// we need to store the TLS cert as a chain since Web server should send the
	// entire certificate chain minus the root
	err = crypt.SavePemCertChain(ts.TLSCertPath, cert, tlsCaCert.Raw)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Could not save TLS certificate")
	}

	tlsCertificateBytes, err := ioutil.ReadFile(ts.TLSCertPath)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Could not read TLS cert")
	}

	tlsDigest, err := crypt.GetCertHashFromPemInHex(tlsCertificateBytes, crypto.SHA384)
	if err != nil {
		return errors.Wrap(err, "tasks/tls:Run() Unable to get digest of TLS certificate")
	}
	*ts.TLSCertDigestPtr = tlsDigest
	fmt.Println("TLS Certificate Digest : ", tlsDigest)

	return nil
}

func (ts TLS) Validate() error {
	log.Trace("tasks/tls:Validate() Entering")
	defer log.Trace("tasks/tls:Validate() Leaving")

	fmt.Fprintln(ts.ConsoleWriter, "Validating tls setup...")
	_, err := os.Stat(ts.TLSCertPath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/tls:Validate() TLSCertFile is not configured")
	}
	_, err = os.Stat(ts.TLSKeyPath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/tls:Validate() TLSKeyFile is not configured")
	}
	return nil
}

func (ts TLS) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, tlsEnvHelpPrompt, ts.envPrefix, tlsEnvHelp)
	fmt.Fprintln(w, "")
}

func (ts TLS) SetName(n, e string) {
	ts.commandName = n
	ts.envPrefix = setup.PrefixUnderscroll(e)
}
