/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	faultsConst "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

func NewXmlMeasurementLogIntegrity(flavorID uuid.UUID, flavorLabel string, expectedCumulativeHash string) (Rule, error) {

	rule := xmlMeasurementLogIntegrity{
		flavorId:               flavorID,
		flavorLabel:            flavorLabel,
		expectedCumulativeHash: expectedCumulativeHash,
	}

	return &rule, nil
}

type xmlMeasurementLogIntegrity struct {
	flavorId               uuid.UUID
	flavorLabel            string
	expectedCumulativeHash string
}

// - If the xml event log is missing, create a XmlMeasurementLogMissing fault.
// - If there is any error parsing the event log xml, create a XmlMeasurementLogInvalid fault.
// - If there is no an xml event log in the manifest that corresponds to the flavor, create a
//   XmlMeasurementLogMissing fault.
// - If PCR15 is not present in the manifest, we can't verify integrity so generate a PcrEventLogMissing
//   fault.
// - Otherwise, replay the events in the hostmanifest, comparing the cumulative hash against
//   the flavor's cumulative hash, the manifest's cumulative has and the event log measurement
//   in PCR15.
func (rule *xmlMeasurementLogIntegrity) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = faultsConst.RuleXmlMeasurementLogIntegrity
	result.Rule.FlavorName = &rule.flavorLabel
	result.Rule.ExpectedValue = &rule.expectedCumulativeHash
	result.Rule.Markers = append(result.Rule.Markers, hvs.FlavorPartSoftware)
	result.Rule.FlavorID = &rule.flavorId

	if hostManifest.MeasurementXmls == nil || len(hostManifest.MeasurementXmls) == 0 {
		result.Faults = append(result.Faults, newXmlEventLogMissingFault(rule.flavorId))
	} else {
		actualMeasurements, actualMeasurementsXml, err := getMeasurementAssociatedWithFlavor(hostManifest, rule.flavorId, rule.flavorLabel)
		if err != nil {
			result.Faults = append(result.Faults, newXmlMeasurementLogInvalidFault())
		} else if actualMeasurements == nil {
			result.Faults = append(result.Faults, newXmlEventLogMissingFault(rule.flavorId))
		} else {

			// Compare the calculated hash (from replay) against three other measurements...
			// - The 'expected cumulative hash' from the flavor/measurement
			// - The 'actual cumulative hash' from the host manifest
			// - The hash value from pcr event log that was captured during MLE by tbootxm

			// replay the xml event log and calculate the cumulative hash
			calculatedHash, err := rule.replay(actualMeasurementsXml)
			if err != nil {
				return nil, errors.Wrapf(err, "There was an error during the 'replay' of the xml event log.")
			}

			if calculatedHash != actualMeasurements.CumulativeHash {
				// calculated replay hash didn't match what the actual measurement
				fault := newXmlMeasurementValueMismatch(actualMeasurements.CumulativeHash, calculatedHash)
				result.Faults = append(result.Faults, fault)
			} else if calculatedHash != rule.expectedCumulativeHash {
				// replay did not match what was defined in the flavor
				fault := newXmlMeasurementValueMismatch(rule.expectedCumulativeHash, calculatedHash)
				result.Faults = append(result.Faults, fault)
			} else {
				// now check the pcr event logs...
				pcrNewEventLogs, err := hostManifest.PcrManifest.GetEventLogCriteria(hvs.SHA256, hvs.PCR15)

				if err != nil {
					// the event log was missing from the manifest...
					fault := newPcrEventLogMissingFault(hvs.PCR15, hvs.SHA256)
					result.Faults = append(result.Faults, fault)
				} else {
					// If the pcr event log is present, see if it has a measurement that
					// matches the flavor label.  The event log label will be the concatenation
					// of the flavor name and the flavor id similar to...
					// 'ISecL_Default_Application_Flavor_v2.1_TPM2.0-339a7ac6-b8be-4356-ab34-be6e3bdfa1ed'
					pcrEventLogMeasurement := ""
					labelToMatch := rule.flavorLabel + "-" + rule.flavorId.String()

					for _, eventLog := range pcrNewEventLogs {
						for _, tag := range eventLog.Tags {
							if tag == labelToMatch {
								pcrEventLogMeasurement = eventLog.Measurement
								break
							}
						}
						if strings.Contains(rule.flavorLabel, constants.DefaultSoftwareFlavorPrefix) ||
							strings.Contains(rule.flavorLabel, constants.DefaultWorkloadFlavorPrefix) {
							for _, tag := range eventLog.Tags {
								if strings.HasPrefix(tag, rule.flavorLabel) {
									pcrEventLogMeasurement = eventLog.Measurement
									break
								}
							}
						}
					}
					if pcrEventLogMeasurement == "" {
						// the pcr event did not have a measurement with the flavor label
						fault := hvs.Fault{
							Name:          faultsConst.FaultXmlMeasurementValueMismatch,
							Description:   fmt.Sprintf("The pcr event log did not contain a measurement with label '%s'", rule.flavorLabel),
							ExpectedValue: &pcrEventLogMeasurement,
							ActualValue:   &calculatedHash,
						}
						result.Faults = append(result.Faults, fault)
					} else {

						// The cumulative hash from the software flavor measurements are sha384 hashes.
						// That value is extended to PCR15 as sha256 (i.e what is in the host manifest).
						// Create a sha256 hash from the calculated hash and compare it to what is stored in PCR 15.
						calculatedSha384Bytes, _ := hex.DecodeString(calculatedHash)

						hash := sha256.New()
						_, err = hash.Write(calculatedSha384Bytes)
						if err != nil {
							return nil, errors.Wrapf(err, "Failed to write calculated hash")
						}

						calculatedSha256Bytes := hash.Sum(nil)

						calculatedSha256String := hex.EncodeToString(calculatedSha256Bytes)
						if calculatedSha256String != pcrEventLogMeasurement {
							// the calculated hash did not match the measurement captured in the pcr event log
							fault := hvs.Fault{
								Name:          faultsConst.FaultXmlMeasurementValueMismatch,
								Description:   fmt.Sprintf("Host XML measurement log final hash with value '%s' does not match the pcr event log measurement '%s'", calculatedSha256String, pcrEventLogMeasurement),
								ExpectedValue: &pcrEventLogMeasurement,
								ActualValue:   &calculatedSha256String,
							}
							result.Faults = append(result.Faults, fault)
						}
					}
				}
			}
		}
	}

	return &result, nil
}

// this function calculates the cumulative hash of the event log using the
// raw xml (since the go struct does not maintain order).
func (rule *xmlMeasurementLogIntegrity) replay(measurementsXml []byte) (string, error) {

	cumulativeHash := make([]byte, sha512.Size384)
	orderedMeasurements, err := rule.getOrderedMeasurements(measurementsXml)
	if err != nil {
		return "", errors.Wrap(err, "Error in getting ordered Measurements values")
	}

	for _, measurement := range orderedMeasurements {
		hash := sha512.New384()
		measurementBytes, err := hex.DecodeString(measurement)
		if err != nil {
			return "", errors.Wrapf(err, "Invalid measurement in xml: '%s'", measurement)
		}

		_, err = hash.Write(cumulativeHash)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to write cumulative hash")
		}
		_, err = hash.Write(measurementBytes)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to write measurements")
		}

		cumulativeHash = hash.Sum(nil)
	}

	return hex.EncodeToString(cumulativeHash), nil
}

func (rule *xmlMeasurementLogIntegrity) getOrderedMeasurements(measurementsXml []byte) ([]string, error) {

	var measurements []string
	reader := bytes.NewReader(measurementsXml)
	xmlDecoder := xml.NewDecoder(reader)
	inMeasurementTag := false

	for {
		token, err := xmlDecoder.Token()

		if err != nil && err != io.EOF {
			return nil, errors.Wrapf(err, "Error parsing measurement xml")
		}

		// EOF
		if token == nil {
			break
		}

		if measurement, ok := token.(xml.CharData); ok && inMeasurementTag {
			measurements = append(measurements, string(measurement))
			inMeasurementTag = false
		} else if start, ok := token.(xml.StartElement); ok {
			if start.Name.Local == "File" || start.Name.Local == "Dir" || start.Name.Local == "Symlink" {
				inMeasurementTag = true
			}
		} else {
			inMeasurementTag = false
		}
	}

	return measurements, nil
}
