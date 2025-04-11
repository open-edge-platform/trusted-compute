/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/pem"
	"github.com/pkg/errors"
	"io/ioutil"
	"os"
)

func (handler *requestHandlerImpl) GetAikDerBytes(aikCertPath string) ([]byte, error) {
	aikBytes, err := GetAikPem(aikCertPath)
	if err != nil {
		return nil, err
	}

	aikDer, _ := pem.Decode(aikBytes)
	if aikDer == nil {
		return nil, errors.New("There was an error parsing the aik's der bytes")
	}

	return aikDer.Bytes, nil
}

func GetAikPem(aikCertPath string) ([]byte, error) {
	if _, err := os.Stat(aikCertPath); os.IsNotExist(err) {
		return nil, errors.Wrapf(err, "AIK %s does not exist", aikCertPath)
	}

	aikPem, err := ioutil.ReadFile(aikCertPath)
	if err != nil {
		return nil, errors.Wrap(err, "Error reading aik")
	}

	return aikPem, nil
}
