/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"io"
	"os"
)

const intermediateCAEnvHelpPrompt = "Following environment variables are required for intermediate-ca setup:"

type IntermediateCa struct {
	ConsoleWriter    io.Writer
	Config           *config.CACertConfig
	envPrefix        string
	commandName      string
	SerialNumberPath string
	CaAttribs        map[string]constants.CaAttrib
}

func (ca IntermediateCa) createIntermediateCACert(cfg *config.CACertConfig, cn string) (privKey crypto.PrivateKey, cert []byte, err error) {
	log.Trace("tasks/intermediate_ca:createIntermediateCACert() Entering")
	defer log.Trace("tasks/intermediate_ca:createIntermediateCACert() Leaving")

	rCaAttr := constants.GetCaAttribs(constants.Root, ca.CaAttribs)

	privKey, pubKey, err := crypt.GenerateKeyPair(constants.DefaultKeyAlgorithm, constants.DefaultKeyAlgorithmLength)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not generate key pair")
	}
	caCertTemplate, err := getCACertTemplate(cfg, cn, rCaAttr.CommonName, pubKey, ca.SerialNumberPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not generate Certificate Template")
	}

	rootCert, rootCAPrivKey, err := crypt.LoadX509CertAndPrivateKey(rCaAttr.CertPath, rCaAttr.KeyPath)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not load root CA certificate")
	}

	cert, err = x509.CreateCertificate(rand.Reader, &caCertTemplate, rootCert, pubKey, rootCAPrivKey)
	if err != nil {
		return nil, nil, errors.Wrap(err, "tasks/intermediate_ca:createIntermediateCACert() Could not create certificate")
	}
	return
}

func (ca IntermediateCa) Run() error {
	log.Trace("tasks/intermediate_ca:Run() Entering")
	defer log.Trace("tasks/intermediate_ca:Run() Leaving")

	fmt.Fprintln(ca.ConsoleWriter, "Running Intermediate CA setup...")
	fs := flag.NewFlagSet("intermediate-ca", flag.ContinueOnError)

	var interCAType string
	fs.StringVar(&interCAType, "type", "", "type of intermediary ca")

	// this represents the list of CAs that we will be creating. Start out with an empty list and then fill it out
	var cas []string

	// there were no specific type that was passed in ... so we will do all of them
	if interCAType == "" {
		cas = constants.GetIntermediateCAs()
	} else {
		if attr := constants.GetCaAttribs(interCAType, ca.CaAttribs); attr.CommonName == "" {
			// the type passed in does not match with one of the supported intermediaries
			return errors.New("tasks/intermediate_ca:Run() could not find matching Intermediary Certificate. Please check help for list of Intermediary CAs supported")
		}
		cas = append(cas, interCAType)
	}

	for _, interCa := range cas {
		fmt.Fprintln(ca.ConsoleWriter, "Creating intermediate CA ", interCa)
		caAttr := constants.GetCaAttribs(interCa, ca.CaAttribs)
		privKey, cert, err := ca.createIntermediateCACert(ca.Config, caAttr.CommonName)
		if err != nil {
			return errors.Wrap(err, "tasks/intermediate_ca:Run() Could not create intemediate CA")
		}

		key, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return errors.Wrap(err, "tasks/intermediate_ca:Run() Could not marshal private key to pkcs8 format error")
		}

		//Store key and certificate
		err = crypt.SavePrivateKeyAsPKCS8(key, caAttr.KeyPath)
		if err != nil {
			return errors.Wrapf(err, "tasks/intermediate_ca:Run() -%v - Could not save private key", interCa)
		}
		err = crypt.SavePemCert(cert, caAttr.CertPath)
		if err != nil {
			return errors.Wrapf(err, "tasks/intermediate_ca:Run() -%v - Could not save certificate", interCa)
		}
	}
	return nil
}

func (ca IntermediateCa) Validate() error {
	log.Trace("tasks/intermediate_ca:Validate() Entering")
	defer log.Trace("tasks/intermediate_ca:Validate() Leaving")

	cas := constants.GetIntermediateCAs()
	for _, interCa := range cas {

		caAttr := constants.GetCaAttribs(interCa, ca.CaAttribs)

		_, err := os.Stat(caAttr.CertPath)
		if os.IsNotExist(err) {
			return errors.Wrapf(err, "tasks/intermediate_ca:Validate() -%v - Intermediary CA Certificate is not configured", interCa)
		}
		_, err = os.Stat(caAttr.KeyPath)
		if os.IsNotExist(err) {
			return errors.Wrapf(err, "tasks/intermediate_ca:Validate() -%v - Intermediary CA Key is not configured", interCa)
		}
	}
	return nil
}

func (ca IntermediateCa) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, intermediateCAEnvHelpPrompt, ca.envPrefix, rootCAEnvHelp)
	fmt.Fprintln(w, "")
}

func (ca IntermediateCa) SetName(n, e string) {
	ca.commandName = n
	ca.envPrefix = setup.PrefixUnderscroll(e)
}
