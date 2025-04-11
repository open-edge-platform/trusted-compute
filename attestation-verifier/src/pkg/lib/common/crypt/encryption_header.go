/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

// EncryptionHeader is used append to the encrypted file during AES GCM encryption mode
type EncryptionHeader struct {
	MagicText            [12]byte
	OffsetInLittleEndian uint32
	Version              [4]byte
	IV                   [12]byte
	EncryptionAlgorithm  [12]byte
}

// EncryptionHeaderExists method is used to check if the file is encryped and returns a boolean value.
// TODO : move it a different package where all the ISecL specific functions are added
func EncryptionHeaderExists(encFilePath string) (bool, error) {

	var encryptionHeader EncryptionHeader
	//open the encrypted file
	encFile, err := os.Open(encFilePath)
	if err != nil {
		return false, err
	}
	defer func() {
		derr := encFile.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()

	magicTextSlice := make([]byte, len(encryptionHeader.MagicText))
	if _, err := encFile.Read(magicTextSlice); err != nil {
		return false, err
	}

	if !strings.Contains(string(magicTextSlice), EncryptionHeaderMagicText) {
		return false, nil
	}
	return true, nil
}
