/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	"reflect"
)

/**
 *
 * @author mullas
 */

// FlavorToManifestConverter is a utility for extracting Manifest from a Flavor
type FlavorToManifestConverter struct {
}

// GetManifestXML extracts the Manifest from the Flavor
func (fmc FlavorToManifestConverter) GetManifestXML(flavor hvs.Flavor) (string, error) {
	log.Trace("flavor/util/flavor_to_manifest_converter:GetManifestXML() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:GetManifestXML() Leaving")

	var manifest taModel.Manifest
	var err error

	manifest = fmc.GetManifestFromFlavor(flavor)

	manifestXML, err := xml.Marshal(manifest)
	if err != nil {
		return "", errors.Wrap(err, "FlavorToManifestConverter: failed to parse Manifest XML")
	}
	return string(manifestXML), nil
}

// getManifestFromFlavor constructs the Manifest from the Flavor
func (fmc FlavorToManifestConverter) GetManifestFromFlavor(flavor hvs.Flavor) taModel.Manifest {
	log.Trace("flavor/util/flavor_to_manifest_converter:getManifestFromFlavor() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:getManifestFromFlavor() Leaving")

	var manifest taModel.Manifest
	manifest.DigestAlg = flavor.Meta.Description[hvs.DigestAlgorithm].(string)
	manifest.Label = flavor.Meta.Description[hvs.Label].(string)
	manifest.Uuid = flavor.Meta.ID.String()
	// extract the manifest types from the flavor based on the measurement types
	var allMeasurements []taModel.FlavorMeasurement
	for _, meT := range flavor.Software.Measurements {
		allMeasurements = append(allMeasurements, meT)
	}
	var allManifestTypes []interface{}
	for _, meT := range allMeasurements {
		allManifestTypes = append(allManifestTypes, fmc.getManifestType(meT))
	}
	for _, maT := range allManifestTypes {
		switch reflect.TypeOf(maT) {
		case reflect.TypeOf(taModel.FileManifestType{}):
			manifest.File = append(manifest.File, maT.(taModel.FileManifestType))
		case reflect.TypeOf(taModel.DirManifestType{}):
			manifest.Dir = append(manifest.Dir, maT.(taModel.DirManifestType))
		case reflect.TypeOf(taModel.SymlinkManifestType{}):
			manifest.Symlink = append(manifest.Symlink, maT.(taModel.SymlinkManifestType))
		}
	}
	return manifest
}

func (fmc FlavorToManifestConverter) getManifestType(measurement taModel.FlavorMeasurement) interface{} {
	log.Trace("flavor/util/flavor_to_manifest_converter:getManifestType() Entering")
	defer log.Trace("flavor/util/flavor_to_manifest_converter:getManifestType() Leaving")

	var manType interface{}
	switch measurement.Type {
	case taModel.MeasurementTypeFile:
		manType = taModel.FileManifestType{
			Path:       measurement.Path,
			SearchType: measurement.SearchType,
		}
	case taModel.MeasurementTypeDir:
		manType = taModel.DirManifestType{
			Path:       measurement.Path,
			SearchType: measurement.SearchType,
			Include:    measurement.Include,
			Exclude:    measurement.Exclude,
			FilterType: measurement.FilterType,
		}
	case taModel.MeasurementTypeSymlink:
		manType = taModel.SymlinkManifestType{
			Path:       measurement.Path,
			SearchType: measurement.SearchType,
		}
	}
	return manType
}
