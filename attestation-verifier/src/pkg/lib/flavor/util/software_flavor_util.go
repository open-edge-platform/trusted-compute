/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"strings"
)

/**
 *
 * @author mullas
 */

// SoftwareFlavorUtil contains utility functions for working with Software Flavor
type SoftwareFlavorUtil struct {
}

// GetSoftware returns the Software struct per the integrity Measurements sourced from HostManifest
func (sfu SoftwareFlavorUtil) GetSoftware(measurements taModel.Measurement) hvs.Software {
	log.Trace("flavor/util/software_flavor_util:GetSoftware() Entering")
	defer log.Trace("flavor/util/software_flavor_util:GetSoftware() Leaving")

	measurementMap := make(map[string]taModel.FlavorMeasurement)
	var flavorMeasurement taModel.FlavorMeasurement

	// Cleanup Paths for Dir Measurement
	for _, mT := range measurements.Dir {
		(&flavorMeasurement).FromDir(mT)
		measurementMap[sfu.cleanupPaths(mT.Path)] = flavorMeasurement
	}

	// Cleanup Paths for File Measurement
	for _, mT := range measurements.File {
		(&flavorMeasurement).FromFile(mT)
		measurementMap[sfu.cleanupPaths(mT.Path)] = flavorMeasurement
	}

	// Cleanup Paths for Symlink Measurement
	for _, mT := range measurements.Symlink {
		(&flavorMeasurement).FromSymlink(mT)
		measurementMap[sfu.cleanupPaths(mT.Path)] = flavorMeasurement
	}

	var s hvs.Software
	s.Measurements = measurementMap
	s.CumulativeHash = measurements.CumulativeHash
	return s
}

// cleanupPaths is a utility function that cleans up the paths in Measurement XML
func (sfu SoftwareFlavorUtil) cleanupPaths(path string) string {
	log.Trace("flavor/util/software_flavor_util:cleanupPaths() Entering")
	defer log.Trace("flavor/util/software_flavor_util:cleanupPaths() Leaving")

	measuredPath := strings.ReplaceAll(path, "/", "-")
	if strings.LastIndex(measuredPath, "-") == len(measuredPath)-1 {
		measuredPath = strings.Join(strings.Split(measuredPath, "")[1:len(measuredPath)-1], "")
	} else {
		measuredPath = strings.Join(strings.Split(measuredPath, "")[1:], "")
	}
	return measuredPath
}
