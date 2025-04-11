/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"encoding/base64"
	"io"

	"github.com/pkg/errors"
)

// 256 bits = 32 bytes
const keyLen = 32

var defaultB64Encoder = base64.StdEncoding

type CreateDek struct {
	DekStore *string
	Encode   *base64.Encoding
}

func (cd *CreateDek) Run() error {
	if cd.DekStore == nil {
		return errors.New("Key store can not be nil")
	}
	randInt := make([]byte, keyLen)
	if _, err := rand.Read(randInt); err != nil {
		return errors.Wrap(err, "error generating random number")
	}
	b64Enc := cd.encoding()
	*cd.DekStore = b64Enc.EncodeToString(randInt)
	return nil
}

func (cd *CreateDek) Validate() error {
	// checks if DekStore already has valid value in it
	if cd.DekStore == nil {
		return errors.New("Key store can not be nil")
	}
	b64Enc := cd.encoding()
	dek, err := b64Enc.DecodeString(*cd.DekStore)
	if len(dek) != keyLen {
		return errors.New("Dek validation failed")
	}
	return errors.Wrap(err, "Dek validation failed")
}

func (cd *CreateDek) PrintHelp(w io.Writer) {}
func (cd *CreateDek) SetName(n, e string)   {}

func (cd *CreateDek) encoding() *base64.Encoding {
	if cd.Encode != nil {
		return cd.Encode
	}
	return defaultB64Encoder
}
