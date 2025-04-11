/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImageFlavorCreationWithEncryption(t *testing.T) {
	flavorInput, err := GetImageFlavor("Cirros-Enc-Label", true,
		"http://kbs.server.com:20080/v1/keys/73755fda-c910-46be-821f-e8ddeab189e9/transfer",
		"261209df1789073192285e4e408addadb35068421ef4890a5d4d434")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)
}

func TestImageFlavorWithoutEncryption(t *testing.T) {
	flavorInput, err := GetImageFlavor("Cirros-Label", false, "", "")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)
}

func TestSignedImageFlavor(t *testing.T) {
	flavorInput, err := GetImageFlavor("Cirros-Label", false, "", "")
	assert.NoError(t, err)
	flavor, err := json.Marshal(flavorInput)
	assert.NoError(t, err)
	assert.NotNil(t, flavor)

	// Valid case
	GenerateRSAPrivateKey("PKCS8")
	signedFlavor, err := GetSignedImageFlavor(string(flavor), "test.pem")
	assert.NoError(t, err)
	assert.NotNil(t, signedFlavor)
	os.Remove("test.pem")

	//private key location not provided
	signedFlavor, err = GetSignedImageFlavor(string(flavor), "")
	assert.Error(t, err)

	//private key location not found
	signedFlavor, err = GetSignedImageFlavor(string(flavor), "test.pem")
	assert.Error(t, err)

	//Invalid private key
	GenerateRSAPrivateKey("PKCS1")
	signedFlavor, err = GetSignedImageFlavor(string(flavor), "test.pem")
	assert.Error(t, err)
	os.Remove("test.pem")
}

func GenerateRSAPrivateKey(rsaType string) {
	var privkey_bytes []byte
	privkey, _ := rsa.GenerateKey(rand.Reader, 4096)
	if rsaType == "PKCS8" {
		privkey_bytes, _ = x509.MarshalPKCS8PrivateKey(privkey)
	} else if rsaType == "PKCS1" {
		privkey_bytes = x509.MarshalPKCS1PrivateKey(privkey)
	}
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	ioutil.WriteFile("test.pem", privkey_pem, 677)
}
