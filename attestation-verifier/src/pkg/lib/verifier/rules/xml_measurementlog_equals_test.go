/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"encoding/json"
	"encoding/xml"
	"testing"

	"github.com/google/uuid"
	constants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	ta "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/stretchr/testify/assert"
)

func TestXmlMeasurementLogEqualsNoFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// create the manifest
	var testExpectedMeasurement ta.Measurement
	err = xml.Unmarshal([]byte(testMeasurementXml), &testExpectedMeasurement)

	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{testMeasurementXml},
	}

	// apply the manifest to the rule and expect no faults/trusted
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Trusted)
	assert.Equal(t, len(result.Faults), 0)
}

func TestXmlMeasurementLogInvalidData(t *testing.T) {

	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testInvalidSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	_, err = NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.Error(t, err)
}
func TestXmlMeasurementLogEqualsMeasurementLogMissingFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// apply the manifest without xml to the rule and expect XmlEventLogMissingFault, untrusted
	result, err := rule.Apply(&hvs.HostManifest{})
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsMeasurementLogMissingFaultWrongId(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// Change the label in the manifest to invoke FaultXmlMeasurementLogMissing
	// (the expected label will not be found in the rule)
	var wrongId ta.Measurement
	err = xml.Unmarshal([]byte(testCustomMeasurementXml), &wrongId)
	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	wrongId.Uuid = newUuid.String()
	wrongLabelXml, err := xml.Marshal(wrongId)
	assert.NoError(t, err)
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{string(wrongLabelXml)},
	}

	// apply the manifest to the rule, expecting FaultXmlMeasurementLogMissing/untrusted
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogMissing, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsMeasurementLogInvalidFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// manifest with invalid measurement xml
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{"invalidxml"},
	}

	// apply the manifest with invalid xml to the rule and expect FaultXmlMeasurementLogInvalid,
	// untrusted
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogInvalid, result.Faults[0].Name)
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsUnexpectedEntriesFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// Add an additional entries to the manifest (i.e. not in the flavor).
	var unexpectedMeasurements ta.Measurement
	err = xml.Unmarshal([]byte(testMeasurementXml), &unexpectedMeasurements)

	unexpectedMeasurements.File = append(unexpectedMeasurements.File, ta.FileMeasurementType{
		Path:  "/root/malware",
		Value: "79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
	})

	unexpectedMeasurements.Dir = append(unexpectedMeasurements.Dir, ta.DirectoryMeasurementType{
		Path:  "/roots",
		Value: "89770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
	})

	unexpectedMeasurements.Symlink = append(unexpectedMeasurements.Symlink, ta.SymlinkMeasurementType{
		Path:  "/usr/bin/tpmextend",
		Value: "09770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
	})

	unexpectedMeasurementsXml, err := xml.Marshal(unexpectedMeasurements)
	assert.NoError(t, err)
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{string(unexpectedMeasurementsXml)},
	}

	// apply the manifest with the unexpected entries and expect a single FaultXmlMeasurementLogContainsUnexpectedEntries
	// fault with three unexpected entries...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogContainsUnexpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].UnexpectedMeasurements)
	assert.Equal(t, 3, len(result.Faults[0].UnexpectedMeasurements))
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsMissingExpectedEntriesFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// Remove entries to from the manifest (i.e. 'missing' from the flavor)
	var missingMeasurements ta.Measurement
	err = xml.Unmarshal([]byte(testMeasurementXml), &missingMeasurements)
	missingMeasurements.File = missingMeasurements.File[1:]
	missingMeasurements.Dir = missingMeasurements.Dir[1:]

	missingMeasurementsXml, err := xml.Marshal(missingMeasurements)
	assert.NoError(t, err)
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{string(missingMeasurementsXml)},
	}

	// apply the manifest with the missing entries and expect a single FaultXmlMeasurementLogMissingExpectedEntries
	// fault with three missing entries
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogMissingExpectedEntries, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MissingMeasurements)
	assert.Equal(t, 2, len(result.Faults[0].MissingMeasurements))
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsMismatchEntriesFault(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// Change entries in the manifest so that they don't match with
	// the flavor
	var mismatchMeasurements ta.Measurement
	err = xml.Unmarshal([]byte(testMeasurementXml), &mismatchMeasurements)
	mismatchMeasurements.File[0].Value = "invalid"
	mismatchMeasurements.Dir[0].Value = "invalid"

	missingMeasurementsXml, err := xml.Marshal(mismatchMeasurements)
	assert.NoError(t, err)
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{string(missingMeasurementsXml)},
	}

	// apply the manifest with the mismatch entries and expect a single FaultXmlMeasurementLogValueMismatchEntries384
	// fault with three mismatch entries...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 1, len(result.Faults))
	assert.Equal(t, constants.FaultXmlMeasurementLogValueMismatchEntries384, result.Faults[0].Name)
	assert.NotNil(t, result.Faults[0].MismatchMeasurements)
	assert.Equal(t, 2, len(result.Faults[0].MismatchMeasurements))
	t.Logf("Fault description: %s", result.Faults[0].Description)
}

func TestXmlMeasurementLogEqualsMultipleComparisonFaults(t *testing.T) {

	// create the rule
	var softwareFlavor hvs.Flavor
	err := json.Unmarshal([]byte(testSoftwareFlavor), &softwareFlavor)
	assert.NoError(t, err)

	rule, err := NewXmlMeasurementLogEquals(&softwareFlavor)
	assert.NoError(t, err)

	// mix and match missing, unexpected, mismatch faults in the manifest...
	var multipleFaultMeasurements ta.Measurement
	err = xml.Unmarshal([]byte(testMeasurementXml), &multipleFaultMeasurements)

	multipleFaultMeasurements.File = multipleFaultMeasurements.File[1:]                             // missing
	multipleFaultMeasurements.File[0].Value = "invalid"                                             // mismatch
	multipleFaultMeasurements.File = append(multipleFaultMeasurements.File, ta.FileMeasurementType{ // unexpected
		Path:  "/root/malware",
		Value: "79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
	})

	multipleFaultMeasurementsXml, err := xml.Marshal(multipleFaultMeasurements)
	assert.NoError(t, err)
	hostManifest := hvs.HostManifest{
		MeasurementXmls: []string{string(multipleFaultMeasurementsXml)},
	}

	// apply the manifest with the different faults and expect three different
	// faults, each with a single entry each...
	result, err := rule.Apply(&hostManifest)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 3, len(result.Faults))

	for _, fault := range result.Faults {
		switch fault.Name {
		case constants.FaultXmlMeasurementLogMissingExpectedEntries:
			assert.NotNil(t, fault.MissingMeasurements)
			assert.Equal(t, 1, len(fault.MissingMeasurements))
		case constants.FaultXmlMeasurementLogContainsUnexpectedEntries:
			assert.NotNil(t, fault.UnexpectedMeasurements)
			assert.Equal(t, 1, len(fault.UnexpectedMeasurements))
		case constants.FaultXmlMeasurementLogValueMismatchEntries384:
			assert.NotNil(t, fault.MismatchMeasurements)
			assert.Equal(t, 1, len(fault.MismatchMeasurements))
		default:
			assert.Failf(t, "Invalid fault name '%s'", fault.Name)
		}
	}
}
