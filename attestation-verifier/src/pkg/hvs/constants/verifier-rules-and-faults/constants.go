/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

// Verifier Rules
const (
	RulePrefix                      = "rule."
	RuleAikCertificateTrusted       = RulePrefix + "AikCertificateTrusted"
	RuleAssetTagMatches             = RulePrefix + "AssetTagMatches"
	RuleFlavorTrusted               = RulePrefix + "FlavorTrusted"
	RulePcrEventLogEquals           = RulePrefix + "PcrEventLogEquals"
	RulePcrEventLogIncludes         = RulePrefix + "PcrEventLogIncludes"
	RulePcrEventLogIntegrity        = RulePrefix + "PcrEventLogIntegrity"
	RulePcrMatchesConstant          = RulePrefix + "PcrMatchesConstant"
	RuleTagCertificateTrusted       = RulePrefix + "TagCertificateTrusted"
	RuleXmlMeasurementsDigestEquals = RulePrefix + "XmlMeasurementsDigestEquals"
	RuleXmlMeasurementLogEquals     = RulePrefix + "XmlMeasurementLogEquals"
	RulePcrEventLogEqualsExcluding  = RulePrefix + "PcrEventLogEqualsExcluding"
	RuleXmlMeasurementLogIntegrity  = RulePrefix + "XmlMeasurementLogIntegrity"
	RuleImaMeasurementLogIntegrity  = RulePrefix + "ImaMeasurementLogIntegrity"
	RuleImaEventLogEquals           = RulePrefix + "ImaEventLogEquals"
)

// Verifier Faults
const (
	FaultPrefix                                     = "fault."
	FaultAikCertificateExpired                      = FaultPrefix + "AikCertificateExpired"
	FaultAikCertificateMissing                      = FaultPrefix + "AikCertificateMissing"
	FaultAikCertificateNotTrusted                   = FaultPrefix + "AikCertificateNotTrusted"
	FaultAikCertificateNotYetValid                  = FaultPrefix + "AikCertificateNotYetValid"
	FaultAllofFlavorsMissing                        = FaultPrefix + "AllOfFlavorsMissing"
	FaultAssetTagMismatch                           = FaultPrefix + "AssetTagMismatch"
	FaultAssetTagMissing                            = FaultPrefix + "AssetTagMissing"
	FaultAssetTagNotProvisioned                     = FaultPrefix + "AssetTagNotProvisioned"
	FaultFlavorSignatureMissing                     = FaultPrefix + "FlavorSignatureMissing"
	FaultRequiredFlavorTypeMissing                  = FaultPrefix + "RequiredFlavorTypeMissing"
	FaultFlavorSignatureNotTrusted                  = FaultPrefix + "FlavorSignatureNotTrusted"
	FaultFlavorSignatureVerificationFailed          = FaultPrefix + "FlavorSignatureVerificationFailed"
	FaultPcrEventLogContainsUnexpectedEntries       = FaultPrefix + "PcrEventLogContainsUnexpectedEntries"
	FaultPcrEventLogInvalid                         = FaultPrefix + "PcrEventLogInvalid"
	FaultPcrEventLogMissing                         = FaultPrefix + "PcrEventLogMissing"
	FaultPcrEventLogMissingExpectedEntries          = FaultPrefix + "PcrEventLogMissingExpectedEntries"
	FaultPcrManifestMissing                         = FaultPrefix + "PcrManifestMissing"
	FaultPcrValueMismatch                           = FaultPrefix + "PcrValueMismatch"
	FaultPcrValueMismatchSHA1                       = FaultPcrValueMismatch + "SHA1"
	FaultPcrValueMismatchSHA256                     = FaultPcrValueMismatch + "SHA256"
	FaultPcrValueMissing                            = FaultPrefix + "PcrValueMissing"
	FaultTagCertificateExpired                      = FaultPrefix + "TagCertificateExpired"
	FaultTagCertificateMissing                      = FaultPrefix + "TagCertificateMissing"
	FaultTagCertificateNotTrusted                   = FaultPrefix + "TagCertificateNotTrusted"
	FaultTagCertificateNotYetValid                  = FaultPrefix + "TagCertificateNotYetValid"
	FaultXmlMeasurementLogContainsUnexpectedEntries = FaultPrefix + "XmlMeasurementLogContainsUnexpectedEntries"
	FaultXmlMeasurementLogInvalid                   = FaultPrefix + "XmlMeasurementLogInvalid"
	FaultXmlMeasurementLogMissing                   = FaultPrefix + "XmlMeasurementLogMissing"
	FaultXmlMeasurementLogMissingExpectedEntries    = FaultPrefix + "XmlMeasurementLogMissingExpectedEntries"
	FaultXmlMeasurementLogValueMismatchEntries384   = FaultPrefix + "XmlMeasurementLogValueMismatchEntriesSha384"
	FaultXmlMeasurementsDigestValueMismatch         = FaultPrefix + "XmlMeasurementsDigestValueMismatch"
	FaultXmlMeasurementValueMismatch                = FaultPrefix + "XmlMeasurementValueMismatch"
	PcrEventLogUnexpectedFields                     = "PcrEventLogUnexpectedFields"
	PcrEventLogMissingFields                        = "PcrEventLogMissingFields"
)

//Builder names
const (
	IntelBuilder  = "Intel Host Trust Policy"
	VmwareBuilder = "VMware Host Trust Policy"
)

//Rule names
const (
	EventlogEqualRule    = "EventlogEqual"
	EventlogIncludesRule = "EventlogIncludes"
	PCRMatchesRule       = "PCRMatches"
)

//Report AdditionalInfo message
const AdditionalInfoDescription = "Listed files have entries with multiple measurements in IMA logs"
