/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	cf "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/common"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// GenericPlatformFlavor represents a flavor that is not specific to any hardware platform
type GenericPlatformFlavor struct {
	TagCertificate *hvs.X509AttributeCertificate
	Vendor         hcConstants.Vendor
}

// GetFlavorPartRaw constructs the Asset Tag flavor from the Tag Certificate of the Generic Platform Flavor
func (gpf GenericPlatformFlavor) GetFlavorPartRaw(name hvs.FlavorPartName) ([]hvs.Flavor, error) {
	log.Trace("flavor/types/generic_platform_flavor:GetFlavorPartRaw() Entering")
	defer log.Trace("flavor/types/generic_platform_flavor:GetFlavorPartRaw() Leaving")

	if name == hvs.FlavorPartAssetTag {
		return gpf.getAssetTagFlavor()
	}

	return nil, errors.New("Unknown flavor part specified by the user")
}

// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
func (gpf GenericPlatformFlavor) GetFlavorPartNames() ([]hvs.FlavorPartName, error) {
	log.Trace("flavor/types/generic_platform_flavor:GetFlavorPartNames() Entering")
	defer log.Trace("flavor/types/generic_platform_flavor:GetFlavorPartNames() Leaving")

	flavorPartList := []hvs.FlavorPartName{hvs.FlavorPartAssetTag}
	return flavorPartList, nil
}

// getAssetTagFlavor Retrieves the asset tag part of the flavor including the certificate and all the key-value pairs
// that are part of the certificate.
func (gpf GenericPlatformFlavor) getAssetTagFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/generic_platform_flavor:getAssetTagFlavor() Entering")
	defer log.Trace("flavor/types/generic_platform_flavor:getAssetTagFlavor() Leaving")

	var errorMessage = "Error during creation of ASSET_TAG flavor"
	var err error

	if gpf.TagCertificate == nil {
		return nil, errors.Errorf("%s - %s", errorMessage, cf.FLAVOR_PART_CANNOT_BE_SUPPORTED().Message)
	}

	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(nil, gpf.TagCertificate, "", hvs.FlavorPartAssetTag, gpf.Vendor)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in Meta section details")
	}
	log.Debugf("flavor/types/generic_platform_flavor:getAssetTagFlavor() New Meta Section: %v", *newMeta)

	// create external section details
	newExt, err := pfutil.GetExternalConfigurationDetails(gpf.TagCertificate)
	if err != nil {
		return nil, errors.Wrap(err, errorMessage+" Failure in External configuration section details")
	}
	log.Debugf("flavor/types/generic_platform_flavor:getAssetTagFlavor() New External Section: %v", *newExt)

	// Create flavor and
	assetTagFlavor := hvs.NewFlavor(newMeta, nil, nil, nil, newExt, nil, nil)

	log.Debugf("flavor/types/generic_platform_flavor:getAssetTagFlavor() New AssetTag Flavor: %v", assetTagFlavor)

	return []hvs.Flavor{*assetTagFlavor}, nil
}
