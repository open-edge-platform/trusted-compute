/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/tasks"
	"io"
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
	os.RemoveAll(path)
}

func mockCertificate(csr string, extraChar bool, differentAlgo bool) string {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, constants.DefaultKeyAlgorithmLength)
	var extensions []pkix.Extension
	var oidExtensionBasicConstraints = []int{2, 5, 29, 19} //export from x509 package
	oidExtensionKeyUsage := []int{2, 5, 29, 15}
	bcExt := pkix.Extension{Id: oidExtensionBasicConstraints, Critical: true, Value: []byte{70, 128, 160, 70}}
	bcExt2 := pkix.Extension{Id: oidExtensionKeyUsage, Critical: true, Value: []byte{70, 128, 160, 70}}
	extensions = append(extensions, bcExt)
	extensions = append(extensions, bcExt2)
	ipAddress := "10.10.10.10"
	AASCommonName := "AAS TLS Certificate"
	var csrTemplate = x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA384WithRSA,
		DNSNames:           []string{ipAddress},
		Subject: pkix.Name{
			CommonName: AASCommonName,
		},
		ExtraExtensions: extensions,
	}
	if differentAlgo == true {
		csrTemplate = x509.CertificateRequest{
			SignatureAlgorithm: x509.MD5WithRSA,
			DNSNames:           []string{ipAddress},
			Subject: pkix.Name{
				CommonName: AASCommonName,
			},
			ExtraExtensions: extensions,
		}
	}
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, keyBytes)
	if extraChar == true {
		csrBytes = append(csrBytes, "test"...)
	}
	buffer := new(bytes.Buffer)
	pem.Encode(buffer, &pem.Block{Type: csr, Bytes: csrBytes})
	csrCert := buffer.String()
	return csrCert
}

func CreateRootCa(path string, mockmp map[string]constants.CaAttrib) {
	c := config.Configuration{}
	rootCa := tasks.RootCa{
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
		CaAttribs:        mockmp,
	}
	rootCa.Run()
}

func CreateIntermediateCa(path string, mockmp map[string]constants.CaAttrib) {
	CreateRootCa(path, mockmp)
	for key, val := range mockmp {
		if key != "root" {
			srcCert, _ := os.Open(constants.GetCaAttribs("root", mockmp).CertPath)
			defer srcCert.Close()
			destCert, _ := os.Create(val.CertPath)
			defer destCert.Close()
			io.Copy(destCert, srcCert)
			srcKey, _ := os.Open(constants.GetCaAttribs("root", mockmp).KeyPath)
			defer srcKey.Close()
			destKey, _ := os.Create(val.KeyPath)
			defer destKey.Close()
			io.Copy(destKey, srcKey)
		}
	}
}
