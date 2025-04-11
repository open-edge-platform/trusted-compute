/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/url"
	"time"
)

// SignedData contains the original byte stream that was signed along with
type SignedData struct {
	Data      []byte `json:"data"` //json formatted VMtrust report.
	Alg       string `json:"hash_alg"`
	Cert      string `json:"cert"` //pem formatted certificate
	Signature []byte `json:"signature"`
}

// GetHexRandomString return a random string of 'length'
func GetHexRandomString(length int) (string, error) {

	bytes, err := GetRandomBytes(length)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

// GetRandomBytes retrieves a byte array of 'length'
func GetRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// GetHashingAlgorithName retrieves a string representation of the hashing algorithm
func GetHashingAlgorithmName(alg crypto.Hash) string {
	switch alg {
	case crypto.SHA1:
		return "SHA1"
	case crypto.SHA256:
		return "SHA-256"
	case crypto.SHA384:
		return "SHA-384"
	case crypto.SHA512:
		return "SHA-512"
	}
	return ""
}

// GetHash returns a byte array to the hash of the data.
// alg indicates the hashing algorithm. Currently, the only supported hashing algorithms
// are SHA1, SHA256, SHA384 and SHA512
func GetHashData(data []byte, alg crypto.Hash) ([]byte, error) {

	if data == nil {
		return nil, fmt.Errorf("Error - data pointer is nil")
	}

	switch alg {
	case crypto.SHA1:
		s := sha1.Sum(data)
		return s[:], nil
	case crypto.SHA256:
		s := sha256.Sum256(data)
		return s[:], nil
	case crypto.SHA384:
		//SHA384 is implemented in the sha512 package
		s := sha512.Sum384(data)
		return s[:], nil
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:], nil
	}

	return nil, fmt.Errorf("Error - Unsupported hashing function %d requested. Only SHA1, SHA256, SHA384 and SHA512 supported", alg)
}

const certSubjectName = "ISecl Self Sign Cert"
const certExpiryDays = 180

// CreateSelfSignedCertAndRSAPrivKeys creates a test certificate. This will be primarily used
// by test functions to make a keypair and certificate that can be used for encryption and signing.
func CreateSelfSignedCertAndRSAPrivKeys(bits ...int) (*rsa.PrivateKey, string, error) {
	if len(bits) > 1 {
		return nil, "", fmt.Errorf("Error: Function only accepts a single parameter - RSA keylength in bits - 1024, 2048 or 3072")
	}
	var rsaBitLength int

	if len(bits) == 0 {
		rsaBitLength = 3072
	} else {
		rsaBitLength = bits[0]
	}

	if !(rsaBitLength == 3072 || rsaBitLength == 2048 || rsaBitLength == 1024) {
		return nil, "", fmt.Errorf("Error: RSA keylength support is only 1024, 2048 or 3072")
	}

	rsaKeyPair, err := rsa.GenerateKey(rand.Reader, rsaBitLength)
	if err != nil {
		return nil, "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{certSubjectName},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * certExpiryDays),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &rsaKeyPair.PublicKey, rsaKeyPair)
	if err != nil {
		return nil, "", fmt.Errorf("Failed to create certificate: %s", err)
	}

	out := &bytes.Buffer{}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return nil, "", fmt.Errorf("Failed to encode cert to PEM: %s", err)
	}
	return rsaKeyPair, out.String(), nil

}

// HashAndSignPKCS1v15 creates a hash and signs it
func HashAndSignPKCS1v15(data []byte, rsaPriv *rsa.PrivateKey, alg crypto.Hash) ([]byte, error) {

	hash, err := GetHashData(data, alg)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, rsaPriv, alg, hash)

}

// GetCertHexSha384 returns SHA384 of a certificate that is stored on disk given a filepath
func GetCertHexSha384(filePath string) (string, error) {
	certPEM, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("cannot read from cert file %s : ", filePath)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: " + err.Error())
	}
	hash, _ := GetHashData(cert.Raw, crypto.SHA384)

	return hex.EncodeToString(hash), nil
}

// RetrieveValidatedPeerCert retrieves the cert of a remote server and matches it against a supplied hash.
// Optionally, if permitted via trustFirstCert accepts the certificate presented by the remote server
func RetrieveValidatedPeerCert(baseUrl string, trustFirstCert bool, trustedThumbprint string, hashAlg crypto.Hash) (*x509.Certificate, error) {

	if !trustFirstCert && trustedThumbprint == "" {
		return nil, fmt.Errorf("trustedThumbprint not provided and trusting retrieved cert not allowed")
	}

	if baseUrl == "" {
		return nil, fmt.Errorf("url to connect cannot be empty")
	}
	url_obj, err := url.Parse(baseUrl)
	if err != nil {
		return nil, fmt.Errorf("could not parse url '%s', error: %s", baseUrl, err)
	}

	var dialString string
	if url_obj.Port() != "" {
		dialString = ":" + url_obj.Port()
	}
	dialString = url_obj.Hostname() + dialString

	//InsecureSkipVerify is set to true as connection is validated manually
	conn, err := tls.Dial("tcp", dialString, &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true})
	if err != nil {
		return nil, fmt.Errorf("could not tcp connect to %s, error: %s: ", dialString, err)
	}

	err = conn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("tls handshake with %s failed, error : %s", dialString, err)
	}

	peerCert := conn.ConnectionState().PeerCertificates[0]

	if trustFirstCert {
		return peerCert, nil
	}

	hash, err := GetHashData(peerCert.Raw, hashAlg)
	if err != nil {
		return nil, err
	}

	if hex.EncodeToString(hash) != trustedThumbprint {
		return nil, fmt.Errorf("retrieved server certificate hash does not match supplied hash: %s calculated hash: %s", hash, trustedThumbprint)
	}

	return peerCert, nil

}

// AesEncrypt encrypts plain bytes using AES key passed as param
func AesEncrypt(data, key []byte) ([]byte, error) {
	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonce := make([]byte, gcm.NonceSize())
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// here we encrypt data using the Seal function
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// AesDecrypt decrypts cipher bytes using AES key passed as param
func AesDecrypt(data, key []byte) ([]byte, error) {
	// generate a new aes cipher using key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("cipher text length cannot be less than %d bytes", nonceSize)
	}

	nonce, data := data[:nonceSize], data[nonceSize:]
	// here we decrypt data using the Open function
	plaintext, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
