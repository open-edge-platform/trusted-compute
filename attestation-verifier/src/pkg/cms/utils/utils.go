/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package utils

import (
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"os"
	"strings"
)

func Message(status bool, message string) map[string]interface{} {
	return map[string]interface{}{"status": status, "message": message}
}

func GetNextSerialNumber(serialNumberPath string) (*big.Int, error) {
	serialNumberNew, err := ReadSerialNumber(serialNumberPath)
	if err != nil && strings.Contains(err.Error(), "no such file") {
		serialNumberNew = big.NewInt(0)
		err = WriteSerialNumber(serialNumberPath, serialNumberNew)
		return serialNumberNew, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
	} else if err != nil {
		return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot read from Serial Number file")
	} else {
		serialNumberNew = serialNumberNew.Add(serialNumberNew, big.NewInt(1))
		err = WriteSerialNumber(serialNumberPath, serialNumberNew)
		if err != nil {
			return nil, errors.Wrap(err, "utils/utils:GetNextSerialNumber() Cannot write to Serial Number file")
		}
		return serialNumberNew, nil
	}
}

func ReadSerialNumber(serialNumberPath string) (*big.Int, error) {
	sn, err := ioutil.ReadFile(serialNumberPath)
	if err != nil {
		return nil, errors.Wrap(err, "utils/utils:ReadSerialNumber() Could not read serial number")
	} else {
		var serialNumber = big.NewInt(0)
		serialNumber.SetBytes(sn)
		return serialNumber, nil
	}
}

func WriteSerialNumber(serialNumberPath string, serialNumber *big.Int) error {
	err := ioutil.WriteFile(serialNumberPath, serialNumber.Bytes(), 0600)
	if err != nil {
		return errors.Wrap(err, "utils/utils:WriteSerialNumber() Failed to write serial-number to file")
	}
	err = os.Chmod(serialNumberPath, 0600)
	if err != nil {
		return errors.Wrap(err, "utils/utils:WriteSerialNumber() Failed to update file permissions")
	}
	return nil
}
