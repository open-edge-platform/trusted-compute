/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package crypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEncryptionHeaderExistsTrue(t *testing.T) {
	encImagePath := "../test/cirros-x86.qcow2_enc"
	isImageEncrypted, err := EncryptionHeaderExists(encImagePath)
	assert.NoError(t, err)
	assert.True(t, isImageEncrypted)
}

func TestEncryptionHeaderExistsFalse(t *testing.T) {
	encImagePath := "../test/cirros-x86.qcow2"
	isImageEncrypted, err := EncryptionHeaderExists(encImagePath)
	assert.NoError(t, err)
	assert.False(t, isImageEncrypted)
}
