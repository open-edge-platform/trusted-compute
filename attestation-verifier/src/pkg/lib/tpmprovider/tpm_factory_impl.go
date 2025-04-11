/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

import (
	"errors"
	"runtime"
)

type LinuxTpmFactoryProvider struct{}

//
// Creates the default TpmFactory that currently uses TSS2 and /dev/tpmrm0
//
func (ltfp LinuxTpmFactoryProvider) NewTpmFactory() (TpmFactory, error) {

	if runtime.GOOS == "linux" {
		return linuxTpmFactory{tctiType: TCTI_DEVICE, conf: "/dev/tpmrm0"}, nil
	} else {
		return nil, errors.New("Unsupported tpm factory platform " + runtime.GOOS)
	}
}
