/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import (
	"errors"
	"os"
	"runtime"
)

type MsSimTpmFactoryProvider struct{}

//
// Implements the TpmFactory using the microsoft simulator (MSSIM) and is only compiled
// with 'unit_test' build flags.
//
func (simtpmf MsSimTpmFactoryProvider) NewTpmFactory() (TpmFactory, error) {

	// if TPM_SIMULATOR_PORT is present in the env, apply that
	// value to 'conf'.
	conf := ""
	port := os.Getenv("TPM_SIMULATOR_PORT")
	if port == "" {
		conf = "host=localhost,port=2321"
	} else {
		conf = "host=localhost,port=" + port
	}

	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType: TCTI_MSSIM, conf: conf}, nil
	} else {
		return nil, errors.New("Unsupported tpm factory platform " + runtime.GOOS)
	}
}
