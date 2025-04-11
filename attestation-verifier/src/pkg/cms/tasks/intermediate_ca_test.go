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

func TestIntermediateCaRunAndValidate(t *testing.T) {
	log.Trace("tasks/intermediate_ca_test:TestIntermediateCaRunAndValidate() Entering")
	defer log.Trace("tasks/intermediate_ca_test:TestIntermediateCaRunAndValidate() Leaving")

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

	ca := IntermediateCa{
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

	err := ca.Run()
	assert.NoError(t, err)
	errValidate := ca.Validate()
	assert.NoError(t, errValidate)
	os.Remove(constants.GetCaAttribs(constants.Tls, mockPathCert).KeyPath)
	errValidationKey := ca.Validate()
	assert.Error(t, errValidationKey)
	os.Remove(constants.GetCaAttribs(constants.Tls, mockPathCert).CertPath)
	errValidationCert := ca.Validate()
	assert.Error(t, errValidationCert)
	ca.PrintHelp(bytes.NewBufferString("test"))
	ca.SetName("test", "test")
	DeleteTestFilePath(path)
}
