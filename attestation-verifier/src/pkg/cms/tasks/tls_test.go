/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"bytes"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestTlsRunAndValidate(t *testing.T) {
	log.Trace("tasks/tls_test:TestTlsRunAndValidate() Entering")
	defer log.Trace("tasks/tls_test:TestTlsRunAndValidate() Leaving")

	path, mockPathCert := CreateTestFilePath()
	c := config.Configuration{}
	rootca := RootCa{
		ConsoleWriter:   os.Stdout,
		CACertConfigPtr: &c.CACert,
		CACertConfig: config.CACertConfig{
			Validity:     constants.DefaultCACertValidity,
			Organization: constants.DefaultOrganization,
			Locality:     constants.DefaultLocality,
			Province:     constants.DefaultProvince,
			Country:      constants.DefaultCountry,
		},
		SerialNumberPath: path + MockSerialNo,
		CaAttribs:        mockPathCert,
	}
	rootca.Run()
	intermediateca := IntermediateCa{
		ConsoleWriter: os.Stdout,
		Config: &config.CACertConfig{
			Validity:     constants.DefaultCACertValidity,
			Organization: constants.DefaultOrganization,
			Locality:     constants.DefaultLocality,
			Province:     constants.DefaultProvince,
			Country:      constants.DefaultCountry,
		},
		SerialNumberPath: path + MockSerialNo,
		CaAttribs:        mockPathCert,
	}

	intermediateca.Run()
	ca := TLS{
		ConsoleWriter:    os.Stdout,
		TLSCertDigestPtr: &c.TlsCertDigest,
		TLSSanList:       "10.10.10.10,9.9.9.9",
		TLSKeyPath:       path + constants.TLSKeyFile,
		TLSCertPath:      path + constants.TLSCertFile,
		SerialNumberPath: path + MockSerialNo,
		CaAttribs:        mockPathCert,
	}

	err := ca.Run()
	assert.NoError(t, err)
	errValidation := ca.Validate()
	assert.NoError(t, errValidation)
	os.Remove(path + constants.TLSKeyFile)
	errValidationKey := ca.Validate()
	assert.Error(t, errValidationKey)
	os.Remove(path + constants.TLSCertFile)
	errValidationCert := ca.Validate()
	assert.Error(t, errValidationCert)
	ca.PrintHelp(bytes.NewBufferString("test"))
	ca.SetName("test", "test")
	DeleteTestFilePath(path)
}

func TestOutboundHost(t *testing.T) {
	log.Trace("tasks/tls_test:TestOutboundHost() Entering")
	defer log.Trace("tasks/tls_test:TestOutboundHost() Leaving")

	host, err := outboundHost()
	assert.NoError(t, err)
	assert.NotNil(t, host)
}
