/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"strings"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// FlavorPart
type FlavorPartName string

const (
	FlavorPartPlatform   FlavorPartName = "PLATFORM"
	FlavorPartOs         FlavorPartName = "OS"
	FlavorPartHostUnique FlavorPartName = "HOST_UNIQUE"
	FlavorPartSoftware   FlavorPartName = "SOFTWARE"
	FlavorPartAssetTag   FlavorPartName = "ASSET_TAG"
	FlavorPartIma        FlavorPartName = "IMA"
)

//FlavorPartsNotFilteredForLatestFlavor is a list of flavor parts that do not need to be cleaned up
// from host-trustcache when custom flavors belonging to these groups are created
var FlavorPartsNotFilteredForLatestFlavor = map[FlavorPartName]bool{
	FlavorPartAssetTag:   true,
	FlavorPartHostUnique: true,
}

// GetFlavorTypes returns a list of flavor types
func GetFlavorTypes() []FlavorPartName {
	log.Trace("flavor/common/flavor_part:GetFlavorTypes() Entering")
	defer log.Trace("flavor/common/flavor_part:GetFlavorTypes() Leaving")

	return []FlavorPartName{FlavorPartPlatform, FlavorPartOs, FlavorPartHostUnique, FlavorPartSoftware, FlavorPartAssetTag, FlavorPartIma}
}

func (fp FlavorPartName) String() string {
	return string(fp)
}

// Parse Converts a string to a FlavorPart.  If the string does
// not match a supported FlavorPart, an error is returned and the
// FlavorPart value 'UNKNOWN'.
func (flavorPart *FlavorPartName) Parse(flavorPartString string) error {

	var result FlavorPartName
	var err error

	switch strings.ToUpper(flavorPartString) {
	case string(FlavorPartPlatform):
		result = FlavorPartPlatform
	case string(FlavorPartOs):
		result = FlavorPartOs
	case string(FlavorPartHostUnique):
		result = FlavorPartHostUnique
	case string(FlavorPartSoftware):
		result = FlavorPartSoftware
	case string(FlavorPartAssetTag):
		result = FlavorPartAssetTag
	case string(FlavorPartIma):
		result = FlavorPartIma
	default:
		err = errors.Errorf("Invalid flavor part string '%s'", flavorPartString)
	}

	*flavorPart = result
	return err
}

// Filter Unique flavor parts from input slice of flavor parts
func FilterUniqueFlavorParts(flavorParts []FlavorPartName) []FlavorPartName {
	if flavorParts != nil && len(flavorParts) > 0 {
		flavorPartMap := make(map[string]bool)
		filteredParts := []FlavorPartName{}
		for _, entry := range flavorParts {
			flavorPart := entry.String()
			if _, value := flavorPartMap[flavorPart]; !value {
				flavorPartMap[flavorPart] = true
				filteredParts = append(filteredParts, entry)
			}
		}
		return filteredParts
	}
	return nil
}
