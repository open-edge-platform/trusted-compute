/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"encoding/json"
	"strings"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type Vendor int

const (
	VendorUnknown Vendor = iota
	VendorIntel
	VendorVMware
	VendorMicrosoft
)

func (vendor Vendor) String() string {
	return [...]string{"UNKNOWN", "INTEL", "VMWARE", "MICROSOFT"}[vendor]
}

func (vendor *Vendor) GetVendorFromOSType(osType string) error {

	var err error

	switch strings.ToLower(osType) {
	case taModel.OsTypeWindows:
		*vendor = VendorMicrosoft
	case taModel.OsTypeVMWare:
		*vendor = VendorVMware
	case taModel.OsTypeLinux:
		*vendor = VendorIntel
	default:
		*vendor = VendorUnknown
		err = errors.Errorf("Could not determine vendor name from OS name '%s'", osType)
	}

	return err
}

func (vendor *Vendor) UnmarshalJSON(b []byte) error {
	var jsonValue string
	if err := json.Unmarshal(b, &jsonValue); err != nil {
		return errors.Wrap(err, "Could not unmarshal Vendor from JSON")
	}
	var err error
	switch strings.ToUpper(jsonValue) {
	case "MICROSOFT":
		*vendor = VendorMicrosoft
	case "VMWARE":
		*vendor = VendorVMware
	case "INTEL":
		*vendor = VendorIntel
	default:
		*vendor = VendorUnknown
		err = errors.Errorf("Provided vendor is not supported. Vendor : '%s'", jsonValue)
	}
	return err
}

func (vendor Vendor) MarshalJSON() ([]byte, error) {
	return json.Marshal(vendor.String())
}
