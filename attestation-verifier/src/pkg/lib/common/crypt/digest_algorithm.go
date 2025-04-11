/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"
)

/**
 *
 * @author mullas
 */

// DigestAlgorithm enumerates the most widely supported hash Algorithm
// Since the standard crypto packages don't have a string representation of the Algorithm
type DigestAlgorithm struct {
	Algorithm crypto.Hash
	Name      string
	Length    int
}

func (d DigestAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Name)
}

// String returns the name of the DigestAlgorithm
func (d DigestAlgorithm) String() string {
	return strings.ToUpper(d.Name)
}

// Prefix returns the common Name of the hashing Algorithm
func (d DigestAlgorithm) Prefix() string {
	return fmt.Sprintf("%s:", strings.ToLower(d.Name))
}

// ZeroHash returns a zero-byte array corresponding to the length of the hash digest
func (d DigestAlgorithm) ZeroHash() []byte {
	return bytes.Repeat(nil, d.Algorithm.Size())
}

// newDigestAlgorithm creates a new instance of the DigestAlgorithm
func newDigestAlgorithm(algorithm crypto.Hash, length int, name string) DigestAlgorithm {
	return DigestAlgorithm{
		Algorithm: algorithm,
		Length:    length,
		Name:      name,
	}
}

// MD5 returns an instance of MD5 DigestAlgorithm
func MD5() DigestAlgorithm {
	return newDigestAlgorithm(crypto.MD5, md5.Size, "MD5")
}

// SHA1 returns an instance of SHA1 DigestAlgorithm
func SHA1() DigestAlgorithm {
	return newDigestAlgorithm(crypto.SHA1, sha1.Size, "SHA1")
}

// SHA256 returns an instance of SHA256 DigestAlgorithm
func SHA256() DigestAlgorithm {
	return newDigestAlgorithm(crypto.SHA256, sha256.Size, "SHA256")
}

// SHA384 returns an instance of SHA384 DigestAlgorithm
func SHA384() DigestAlgorithm {
	return newDigestAlgorithm(crypto.SHA384, sha512.Size384, "SHA384")
}

// SHA512 returns an instance of SHA512 DigestAlgorithm
func SHA512() DigestAlgorithm {
	return newDigestAlgorithm(crypto.SHA512, sha512.Size, "SHA512")
}
