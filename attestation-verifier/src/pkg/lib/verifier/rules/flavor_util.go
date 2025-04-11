/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"encoding/xml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

// lookup the Measurement from the host manifest
func getMeasurementAssociatedWithFlavor(hostManifest *hvs.HostManifest, flavorId uuid.UUID, flavorLabel string) (*model.Measurement, []byte, error) {

	for i, measurementXml := range hostManifest.MeasurementXmls {
		var measurement model.Measurement
		xmlBytes := []byte(measurementXml)

		err := xml.Unmarshal(xmlBytes, &measurement)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "An error occurred parsing measurement xml index %d", i)
		}

		if flavorId.String() == measurement.Uuid {
			return &measurement, xmlBytes, nil
		}

		if (strings.Contains(flavorLabel, constants.DefaultSoftwareFlavorPrefix) ||
			strings.Contains(flavorLabel, constants.DefaultWorkloadFlavorPrefix)) && flavorLabel == measurement.Label {
			return &measurement, xmlBytes, nil
		}
	}

	// not an error, just return nil
	return nil, nil, nil
}
