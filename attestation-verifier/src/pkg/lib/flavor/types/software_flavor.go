/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"encoding/xml"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// SoftwareFlavor represents a flavor consisting primarily of the integrity measurements taken on Software environment
// of the target host
type SoftwareFlavor struct {
	Measurement string `json:"measurement"`
}

// NewSoftwareFlavor returns an instance of SoftwareFlavor
func NewSoftwareFlavor(measurement string) SoftwareFlavor {
	return SoftwareFlavor{Measurement: measurement}
}

// GetSoftwareFlavor creates a SoftwareFlavor that would include all the measurements provided in input.
func (sf *SoftwareFlavor) GetSoftwareFlavor() (*hvs.Flavor, error) {
	log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Entering")
	defer log.Trace("flavor/types/software_flavor:GetSoftwareFlavor() Leaving")

	var errorMessage = "Error during creation of SOFTWARE flavor"
	var measurements taModel.Measurement
	var err error
	err = xml.Unmarshal([]byte(sf.Measurement), &measurements)
	if err != nil {
		return nil, err
	}
	var software = sfutil.GetSoftware(measurements)
	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(nil, nil, sf.Measurement, hvs.FlavorPartSoftware,
		hcConstants.VendorIntel)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/software_flavor:GetSoftwareFlavor() New Meta Section: %v", *newMeta)

	return hvs.NewFlavor(newMeta, nil, nil, nil, nil, &software, nil), nil
}
