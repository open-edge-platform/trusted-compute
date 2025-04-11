/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"encoding/base64"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/pkg/errors"
)

func EncryptString(plainText string, key []byte) (string, error) {
	defaultLog.Trace("utils/host_credential:EncryptString() Entering")
	defer defaultLog.Trace("utils/host_credential:EncryptString() Leaving")

	bytes, err := crypt.AesEncrypt([]byte(plainText), key)
	if err != nil {
		return "", errors.Wrap(err, "Failed to encrypt data")
	}

	return base64.StdEncoding.EncodeToString(bytes), nil
}

func DecryptString(cipherText string, key []byte) (string, error) {
	defaultLog.Trace("utils/host_credential:DecryptString() Entering")
	defer defaultLog.Trace("utils/host_credential:DecryptString() Leaving")

	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decode cipher text")
	}

	bytes, err := crypt.AesDecrypt(cipherBytes, key)
	if err != nil {
		return "", errors.Wrap(err, "Failed to decrypt cipher text")
	}

	return string(bytes), nil
}
