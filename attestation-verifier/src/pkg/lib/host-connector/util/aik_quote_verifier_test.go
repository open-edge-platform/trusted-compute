/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io/ioutil"
	"testing"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
)

func TestVerifyQuoteAndGetPCRManifest(t *testing.T) {
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("../test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)

	decodedEventLogBytes, err := ioutil.ReadFile("../test/sample_measure_log.json")
	assert.NoError(t, err)

	aikCertInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Aik)
	assert.NoError(t, err)
	aikPem, _ := pem.Decode(aikCertInBytes)
	aikCertificate, err := x509.ParseCertificate(aikPem.Bytes)
	assert.NoError(t, err)

	nonceInBytes, err := base64.StdEncoding.DecodeString("EsJ0GRgwSvwn9u3ir9NhidLSKVX5oVn2UJKsH4heHuQ=")
	assert.NoError(t, err)
	verificationNonce, err := GetVerificationNonce(nonceInBytes, tpmQuoteResponse)
	assert.NoError(t, err)
	verificationNonceInBytes, err := base64.StdEncoding.DecodeString(verificationNonce)

	tpmQuoteInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Quote)

	_, buffer, err := VerifyQuoteAndGetPCRDetails(verificationNonceInBytes, tpmQuoteInBytes, aikCertificate)
	_, err = GetPCRManifest(string(decodedEventLogBytes), buffer)
	assert.NoError(t, err)
}

func TestVerifyQuoteAndGetPCRManifestInvalidNonce(t *testing.T) {
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("../test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)

	decodedEventLogBytes, err := ioutil.ReadFile("../test/sample_measure_log.xml")
	assert.NoError(t, err)

	aikCertInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Aik)
	assert.NoError(t, err)
	aikPem, _ := pem.Decode(aikCertInBytes)
	aikCertificate, err := x509.ParseCertificate(aikPem.Bytes)
	assert.NoError(t, err)

	nonceInBytes, err := base64.StdEncoding.DecodeString("xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	assert.NoError(t, err)
	verificationNonce, err := GetVerificationNonce(nonceInBytes, tpmQuoteResponse)
	assert.NoError(t, err)
	verificationNonceInBytes, err := base64.StdEncoding.DecodeString(verificationNonce)

	tpmQuoteInBytes, err := base64.StdEncoding.DecodeString(tpmQuoteResponse.Quote)

	_, buffer, err := VerifyQuoteAndGetPCRDetails(verificationNonceInBytes, tpmQuoteInBytes, aikCertificate)
	_, err = GetPCRManifest(string(decodedEventLogBytes), buffer)
	assert.Error(t, err)
}

func TestGetVerificationNonceAssetTagProvisioned(t *testing.T) {
	var tpmQuoteResponse taModel.TpmQuoteResponse
	b, err := ioutil.ReadFile("../test/sample_tpm_quote.xml")
	assert.NoError(t, err)
	err = xml.Unmarshal(b, &tpmQuoteResponse)
	assert.NoError(t, err)

	nonceInBytes, err := base64.StdEncoding.DecodeString("3FvsK0fpHg5qtYuZHn1MriTMOxc=")
	assert.NoError(t, err)

	//Check error for tag provisioned but not provided
	tpmQuoteResponse.IsTagProvisioned = true
	_, err = GetVerificationNonce(nonceInBytes, tpmQuoteResponse)
	assert.Error(t, err)

	tpmQuoteResponse.AssetTag = "0966d97d182ee8fac40bee16018e762ae46a026f0bb437600e029a755f8745a9a6bb8b3da152ea37ef52f0d855b6622f"
	_, err = GetVerificationNonce(nonceInBytes, tpmQuoteResponse)
	assert.NoError(t, err)
}
