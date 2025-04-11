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
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	clog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"io"
	"os"
	"time"
)

var log = clog.GetDefaultLogger()

type RootCa struct {
	ConsoleWriter   io.Writer
	CACertConfigPtr *config.CACertConfig
	config.CACertConfig
	envPrefix        string
	commandName      string
	SerialNumberPath string
	CaAttribs        map[string]constants.CaAttrib
}

const rootCAEnvHelpPrompt = "Following environment variables are required for root-ca setup:"

var rootCAEnvHelp = map[string]string{
	"CMS_CA_CERT_VALIDITY": "CA Certificate Validity",
	"CMS_CA_ORGANIZATION":  "CA Certificate Organization",
	"CMS_CA_LOCALITY":      "CA Certificate Locality",
	"CMS_CA_PROVINCE":      "CA Certificate Province",
	"CMS_CA_COUNTRY":       "CA Certificate Country",
}

func GetCACertDefaultTemplate(cfg *config.CACertConfig, cn string, parent string, SerialNumberPath string) (x509.Certificate, error) {
	log.Trace("tasks/rootca:GetCACertDefaultTemplate() Entering")
	defer log.Trace("tasks/rootca:GetCACertDefaultTemplate() Leaving")

	tmplt := x509.Certificate{
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{cfg.Organization},
			Country:      []string{cfg.Country},
			Province:     []string{cfg.Province},
			Locality:     []string{cfg.Locality},
		},
		Issuer: pkix.Name{
			CommonName: parent,
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(cfg.Validity, 0, 0),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	serialNumber, err := utils.GetNextSerialNumber(SerialNumberPath)
	tmplt.SerialNumber = serialNumber
	return tmplt, errors.Wrap(err, "tasks/rootca:GetCACertDefaultTemplate() Could not get next serial number for certificate")
}

func getCACertTemplate(cfg *config.CACertConfig, cn string, parCn string, pubKey crypto.PublicKey, SerialNumberPath string) (x509.Certificate, error) {
	log.Trace("tasks/rootca:getCACertTemplate() Entering")
	defer log.Trace("tasks/rootca:getCACertTemplate() Leaving")

	tmplt, err := GetCACertDefaultTemplate(cfg, cn, parCn, SerialNumberPath)
	if err != nil {
		return tmplt, errors.Wrap(err, "tasks/rootca:getCACertTemplate() Could not get CA template")
	}

	tmplt.SignatureAlgorithm, err = crypt.GetSignatureAlgorithm(pubKey)
	if err != nil {
		return tmplt, errors.Wrap(err, "tasks/rootca:getCACertTemplate() Could not read signature from Public Key")
	}
	return tmplt, err
}

func (ca RootCa) createRootCACert(cfg *config.CACertConfig) (privKey crypto.PrivateKey, cert []byte, err error) {
	log.Trace("tasks/rootca:createRootCACert() Entering")
	defer log.Trace("tasks/rootca:createRootCACert() Leaving")

	privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create root key pair")
	}
	caCertTemplate, err := getCACertTemplate(cfg, constants.GetCaAttribs(constants.Root, ca.CaAttribs).CommonName,
		constants.GetCaAttribs(constants.Root, ca.CaAttribs).CommonName, pubKey, ca.SerialNumberPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create CA certificate template")
	}
	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, &caCertTemplate, pubKey, privKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/rootca:createRootCACert() Could not create CA certificate")
	}
	return
}

func (ca RootCa) updateConfig() error {
	log.Trace("tasks/rootca:updateConfig() Entering")
	defer log.Trace("tasks/rootca:updateConfig() Leaving")

	if ca.CACertConfigPtr == nil {
		return errors.New("tasks/rootca:updateConfig() Pointer to CA cert configuration structure can not be nil")
	}

	if ca.CACertConfig.Validity > 0 {
		ca.CACertConfigPtr.Validity = ca.CACertConfig.Validity
	}

	ca.CACertConfigPtr.Organization = ca.CACertConfig.Organization
	ca.CACertConfigPtr.Locality = ca.CACertConfig.Locality
	ca.CACertConfigPtr.Province = ca.CACertConfig.Province
	ca.CACertConfigPtr.Country = ca.CACertConfig.Country

	return nil
}

func (ca RootCa) Run() error {
	log.Trace("tasks/rootca:Run() Entering")
	defer log.Trace("tasks/rootca:Run() Leaving")

	fmt.Fprintln(ca.ConsoleWriter, "Running Root CA setup...")

	err := ca.updateConfig()
	if err != nil {
		return err
	}
	privKey, cert, err := ca.createRootCACert(&ca.CACertConfig)
	if err != nil {
		return errors.Wrap(err, "tasks/rootca:Run() Could not create root certificate")
	}
	key, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return errors.Wrap(err, "tasks/rootca:Run() Could not marshal private key to pkcs8 format error")
	}

	//Store key and certificate
	err = crypt.SavePrivateKeyAsPKCS8(key, constants.GetCaAttribs(constants.Root, ca.CaAttribs).KeyPath)
	if err != nil {
		return errors.Wrap(err, "tasks/rootca:Run() Could not save root private key")
	}
	err = crypt.SavePemCert(cert, constants.GetCaAttribs(constants.Root, ca.CaAttribs).CertPath)
	if err != nil {
		return errors.Wrap(err, "tasks/rootca:Run() Could not save root certificate")
	}

	return nil
}

func (ca RootCa) Validate() error {
	log.Trace("tasks/rootca:Validate() Entering")
	defer log.Trace("tasks/rootca:Validate() Leaving")

	_, err := os.Stat(constants.GetCaAttribs(constants.Root, ca.CaAttribs).CertPath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/rootca:Validate() RootCACertFile is not configured")
	}
	_, err = os.Stat(constants.GetCaAttribs(constants.Root, ca.CaAttribs).KeyPath)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/rootca:Validate() RootCAKeyFile is not configured")
	}
	return nil
}

func (ca RootCa) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, rootCAEnvHelpPrompt, ca.envPrefix, rootCAEnvHelp)
	fmt.Fprintln(w, "")
}

func (ca RootCa) SetName(n, e string) {
	ca.commandName = n
	ca.envPrefix = setup.PrefixUnderscroll(e)
}
