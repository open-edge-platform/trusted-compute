/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

var MockSerialNo = "serial-number"
var path = "test/"

func TestUtils(t *testing.T) {
	os.MkdirAll(path, os.ModePerm)
	serialNo, _ := GetNextSerialNumber(path + MockSerialNo)
	if !(serialNo.String() == "0") {
		t.Errorf("Unequal value of serial no %q", serialNo.String())
	}
	serialNo1, _ := GetNextSerialNumber(path + MockSerialNo)
	if !(serialNo1.String() == "1") {
		t.Errorf("Unequal value of serial no %q", serialNo1.String())
	}
	os.RemoveAll(path)
}

func TestUtilsImproperPermission(t *testing.T) {
	os.MkdirAll(path, os.ModePerm)
	GetNextSerialNumber(path + MockSerialNo)
	os.Chmod(path+MockSerialNo, 0000)
	_, err := GetNextSerialNumber(path + MockSerialNo)
	assert.NoError(t, err)
	os.RemoveAll(path)
}

func TestMessage(t *testing.T) {
	inter := Message(true, "test")
	if !(inter["message"] == "test") {
		t.Errorf("error")
	}
}
