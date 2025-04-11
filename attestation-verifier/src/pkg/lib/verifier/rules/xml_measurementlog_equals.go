/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"fmt"
	"reflect"

	"github.com/google/uuid"
	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	ta "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

func NewXmlMeasurementLogEquals(softwareFlavor *hvs.Flavor) (Rule, error) {

	meta := softwareFlavor.Meta
	if reflect.DeepEqual(meta, hvs.Meta{}) {
		return nil, errors.New("'Meta' was not provided in the software flavor")
	}

	if len(meta.Description[hvs.Label].(string)) == 0 {
		return nil, errors.New("The software flavor label was not provided")
	}

	if softwareFlavor.Software == nil {
		return nil, errors.New("The flavor does not contain 'software' data.")
	}

	rule := xmlMeasurementLogEquals{
		flavorID:    meta.ID,
		flavorLabel: meta.Description[hvs.Label].(string),
	}

	for _, measurement := range softwareFlavor.Software.Measurements {
		if measurement.Type == ta.MeasurementTypeFile {
			rule.expectedFileMeasurements = append(rule.expectedFileMeasurements, measurement)
		} else if measurement.Type == ta.MeasurementTypeDir {
			rule.expectedDirMeasurements = append(rule.expectedDirMeasurements, measurement)
		} else if measurement.Type == ta.MeasurementTypeSymlink {
			rule.expectedSymlinkMeasurements = append(rule.expectedSymlinkMeasurements, measurement)
		} else {
			return nil, errors.Errorf("Unknown measurement type '%s'", measurement.Type)
		}
	}

	return &rule, nil
}

type xmlMeasurementLogEquals struct {
	flavorID                    uuid.UUID
	flavorLabel                 string
	expectedFileMeasurements    []ta.FlavorMeasurement
	expectedDirMeasurements     []ta.FlavorMeasurement
	expectedSymlinkMeasurements []ta.FlavorMeasurement
}

// - If the xml event log is missing, create a XmlMeasurementLogMissing fault.
// - If there is any error parsing the event log xml, create a XmlMeasurementLogInvalid fault.
// - If there is no an xml event log in the manifest that corresponds to the flavor, create a
//   XmlMeasurementLogMissing fault.
// - If the host manifest's xml event log is empty, create a XmlMeasurementLogMissing fault.
// - Otherwise, compare the expected/actual and generate faults in createEventLogFaults()
func (rule *xmlMeasurementLogEquals) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RuleXmlMeasurementLogEquals
	result.Rule.FlavorName = &rule.flavorLabel
	result.Rule.Markers = append(result.Rule.Markers, hvs.FlavorPartSoftware)
	result.Rule.FlavorID = &rule.flavorID

	result.Rule.ExpectedMeasurements = append(result.Rule.ExpectedMeasurements, rule.expectedFileMeasurements...)
	result.Rule.ExpectedMeasurements = append(result.Rule.ExpectedMeasurements, rule.expectedDirMeasurements...)
	result.Rule.ExpectedMeasurements = append(result.Rule.ExpectedMeasurements, rule.expectedSymlinkMeasurements...)

	if hostManifest.MeasurementXmls == nil || len(hostManifest.MeasurementXmls) == 0 {
		result.Faults = append(result.Faults, newXmlEventLogMissingFault(rule.flavorID))
	} else {
		actualMeasurements, _, err := getMeasurementAssociatedWithFlavor(hostManifest, rule.flavorID, rule.flavorLabel)
		if err != nil {
			result.Faults = append(result.Faults, newXmlMeasurementLogInvalidFault())
		} else if actualMeasurements == nil {
			result.Faults = append(result.Faults, newXmlEventLogMissingFault(rule.flavorID))
		} else {
			eventLogFaults, err := rule.createEventLogFaults(actualMeasurements)
			if err != nil {
				return nil, err
			}

			result.Faults = append(result.Faults, eventLogFaults...)
		}
	}

	return &result, nil
}

// Compare the 'expected' File/Dir/SymLink mesaurements against the 'actual' measurements.
// If the measurement's 'Path' is the same, but the 'Value' is not, generate a 'mismatch' fault.
// If the 'actual' contains a 'Path' that is not in 'expected', generate a 'unexpected entry' fault.
// If the 'expected' contains a 'Path' that is not in 'actual', genereate a 'missing entry fault.
func (rule *xmlMeasurementLogEquals) createEventLogFaults(actualMeasurements *ta.Measurement) ([]hvs.Fault, error) {

	faults := make([]hvs.Fault, 0)
	var missingMeasurements []ta.FlavorMeasurement
	var unexpectedMeasurements []ta.FlavorMeasurement
	var mismatchMeasurements []ta.FlavorMeasurement

	// build indexes to compare the File entries
	expectedFileIndex := createMeasurementIndex(rule.expectedFileMeasurements)
	actualFileIndex := createMeasurementIndex(rule.filesToFlavorMeasurements(actualMeasurements.File))

	// build indexes to compare the Dir entries
	expectedDirIndex := createMeasurementIndex(rule.expectedDirMeasurements)
	actualDirIndex := createMeasurementIndex(rule.dirsToFlavorMeasurements(actualMeasurements.Dir))

	// build indexes to compare the Symlink entries
	expectedSymlinkIndex := createMeasurementIndex(rule.expectedSymlinkMeasurements)
	actualSymlinkIndex := createMeasurementIndex(rule.symlinksToFlavorMeasurements(actualMeasurements.Symlink))

	// group all of the indexes in an array to interate over
	allIndexes := [][]map[string]ta.FlavorMeasurement{
		{expectedFileIndex, actualFileIndex},
		{expectedDirIndex, actualDirIndex},
		{expectedSymlinkIndex, actualSymlinkIndex},
	}

	// iterate over 'allIndexes' and add measurements to the lists of
	// 'missing', 'mismatch' or 'unexepected'
	for _, indexesToCompare := range allIndexes {
		expectedIndex := indexesToCompare[0]
		actualIndex := indexesToCompare[1]

		for expectedPath, expectedFileMeasurement := range expectedIndex {
			if actualFileMeasurement, ok := actualIndex[expectedPath]; ok {
				if actualFileMeasurement.Value != expectedFileMeasurement.Value {
					// the path matches but the measurement is different --> "mismatch"
					mismatchMeasurements = append(mismatchMeasurements, expectedFileMeasurement)
				} // else ok, it matches --> no fault

				// remove the item from the index so that any remainders after this loop will be
				// considered 'unexpected'
				delete(actualIndex, expectedPath)
			} else {
				// the actual measurement is not in expected --> 'missing'
				missingMeasurements = append(missingMeasurements, expectedFileMeasurement)
			}
		}

		// any remainders in 'actual' are 'unexpected'
		for _, remainingActualMeasurement := range actualIndex {
			unexpectedMeasurements = append(unexpectedMeasurements, remainingActualMeasurement)
		}
	}

	// roll up all of the missing measurements into a single fault
	if len(missingMeasurements) > 0 {
		fault := hvs.Fault{
			Name:                constants.FaultXmlMeasurementLogMissingExpectedEntries,
			Description:         fmt.Sprintf("XML measurement log for flavor %s missing %d expected entries.", rule.flavorID, len(missingMeasurements)),
			FlavorId:            &rule.flavorID,
			MissingMeasurements: missingMeasurements,
		}

		faults = append(faults, fault)
	}

	// roll up all of the unexpected measurements into a single fault
	if len(unexpectedMeasurements) > 0 {
		fault := hvs.Fault{
			Name:                   constants.FaultXmlMeasurementLogContainsUnexpectedEntries,
			Description:            fmt.Sprintf("XML measurement log of flavor %s contains %d unexpected entries.", rule.flavorID, len(unexpectedMeasurements)),
			FlavorId:               &rule.flavorID,
			UnexpectedMeasurements: unexpectedMeasurements,
		}

		faults = append(faults, fault)
	}

	// roll up all of the mismatched measurements into a single fault
	if len(mismatchMeasurements) > 0 {
		fault := hvs.Fault{
			Name:                 constants.FaultXmlMeasurementLogValueMismatchEntries384,
			Description:          fmt.Sprintf("XML measurement log for flavor %s contains %d entries for which the values are modified.", rule.flavorID, len(mismatchMeasurements)),
			FlavorId:             &rule.flavorID,
			MismatchMeasurements: mismatchMeasurements,
		}

		faults = append(faults, fault)
	}

	return faults, nil
}

// create a map/index that can be used for comparison in createEventLogFaults
func createMeasurementIndex(flavorMeasurements []ta.FlavorMeasurement) map[string]ta.FlavorMeasurement {
	comparisonIndex := make(map[string]ta.FlavorMeasurement, len(flavorMeasurements))

	for _, flavorMeasurement := range flavorMeasurements {
		comparisonIndex[flavorMeasurement.Path] = flavorMeasurement
	}

	return comparisonIndex
}

// convert FileMeasurementType to ta.FlavorMeasurementType
func (rule *xmlMeasurementLogEquals) filesToFlavorMeasurements(fileMeasurements []ta.FileMeasurementType) []ta.FlavorMeasurement {
	flavorMeasurements := make([]ta.FlavorMeasurement, len(fileMeasurements))
	var flavorMeasurement ta.FlavorMeasurement

	for i, fileMeasurementType := range fileMeasurements {
		(&flavorMeasurement).FromFile(fileMeasurementType)
		flavorMeasurements[i] = flavorMeasurement
	}

	return flavorMeasurements
}

// convert DirectoryMeasurementType to ta.FlavorMeasurementType
func (rule *xmlMeasurementLogEquals) dirsToFlavorMeasurements(dirMeasurements []ta.DirectoryMeasurementType) []ta.FlavorMeasurement {
	flavorMeasurements := make([]ta.FlavorMeasurement, len(dirMeasurements))
	var flavorMeasurement ta.FlavorMeasurement

	for i, dirMeasurementType := range dirMeasurements {
		(&flavorMeasurement).FromDir(dirMeasurementType)
		flavorMeasurements[i] = flavorMeasurement
	}

	return flavorMeasurements
}

// convert SymlinkMeasurementType to ta.FlavorMeasurementType
func (rule *xmlMeasurementLogEquals) symlinksToFlavorMeasurements(symlinkMeasurements []ta.SymlinkMeasurementType) []ta.FlavorMeasurement {
	flavorMeasurements := make([]ta.FlavorMeasurement, len(symlinkMeasurements))
	var flavorMeasurement ta.FlavorMeasurement

	for i, symlinkMeasurementType := range symlinkMeasurements {
		(&flavorMeasurement).FromSymlink(symlinkMeasurementType)
		flavorMeasurements[i] = flavorMeasurement
	}

	return flavorMeasurements
}
