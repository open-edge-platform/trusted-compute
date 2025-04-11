/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"crypto/rand"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"os"
)

var MockMp = map[string]constants.CaAttrib{
	constants.Root:      {constants.DefaultRootCACommonName, constants.RootCaCertFile, constants.RootCaKeyFile},
	constants.Tls:       {constants.DefaultTlsCACommonName, constants.TlsCaCertFile, constants.TlsCaKeyFile},
	constants.TlsClient: {constants.DefaultTlsClientCaCommonName, constants.TlsClientCaCertFile, constants.TlsClientCaKeyFile},
	constants.Signing:   {constants.DefaultSigningCaCommonName, constants.SigningCaCertFile, constants.SigningCaKeyFile},
}

var MockSerialNo = "serial-number"

func GenerateRandString() string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var ll = len(letters)
	var length = 10
	b := make([]byte, length)
	rand.Read(b)
	for i := 0; i < length; i++ {
		b[i] = letters[int(b[i])%ll]
	}
	return string(b)
}

func CreateTestFilePath() (string, map[string]constants.CaAttrib) {
	path := "./" + GenerateRandString() + "/"
	os.Mkdir(path, os.ModePerm)
	var mockPathCert = make(map[string]constants.CaAttrib)

	for key, value := range MockMp {
		eachPath := new(constants.CaAttrib)
		eachPath.CommonName = value.CommonName
		eachPath.CertPath = path + value.CertPath
		eachPath.KeyPath = path + value.KeyPath
		mockPathCert[key] = *eachPath
	}
	return path, mockPathCert
}

func DeleteTestFilePath(path string) {
	log.Trace("tasks/common_test:DeleteTestFilePath() Entering")
	defer log.Trace("tasks/common_test:DeleteTestFilePath() Leaving")
	os.RemoveAll(path)
}
