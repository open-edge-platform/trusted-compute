/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

import (
	"encoding/binary"
	"os"

	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type secureBootParser struct{}

func (secureBootParser *secureBootParser) Init() error {
	return nil
}

func (secureBootParser *secureBootParser) Parse(hostInfo *model.HostInfo) error {

	if hostInfo.HardwareFeatures.UEFI == nil {
		hostInfo.HardwareFeatures.UEFI = &model.UEFI{}
	}
	// if the secure-boot file does not exists (ex. on older Purley systems) then assume
	// secure boot is disabled
	if _, err := os.Stat(secureBootFile); os.IsNotExist(err) {
		hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false
		return nil
	}

	// otherwise, read 'secureBootFile' to determine if secure-boot is enabled
	file, err := os.Open(secureBootFile)
	if err != nil {
		return errors.Wrapf(err, "Failed to open secure-boot file %q", secureBootFile)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Errorf("Failed close secure-boot file %q: %+v", secureBootFile, err)
		}
	}()

	// the 1st four bytes of the file are efi attributes
	var attributes uint32
	err = binary.Read(file, binary.LittleEndian, &attributes)
	if err != nil {
		return errors.Errorf("The secure-boot file %q is too small.  SecureBoot will be considered disabled", secureBootFile)
	}

	// now read the byte that indicated enabled/disabled (disabled == 0)
	var enabled byte
	err = binary.Read(file, binary.LittleEndian, &enabled)
	if err != nil {
		return errors.Errorf("The secure-boot file %q is too small.  SecureBoot will be considered disabled", secureBootFile)
	}

	if enabled == 0 {
		hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled = false
	} else {
		hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled = true
	}

	return nil
}
