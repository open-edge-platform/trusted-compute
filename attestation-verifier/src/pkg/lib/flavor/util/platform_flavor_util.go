/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/rsa"
	"encoding/xml"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

/**
 *
 * @author mullas
 */

// PlatformFlavorUtil is used to group a collection of utility functions dealing with PlatformFlavor
type PlatformFlavorUtil struct {
}

// GetMetaSectionDetails returns the Meta instance from the HostManifest
func (pfutil PlatformFlavorUtil) GetMetaSectionDetails(hostDetails *taModel.HostInfo, tagCertificate *hvs.X509AttributeCertificate,
	xmlMeasurement string, flavorPartName hvs.FlavorPartName, vendor hcConstants.Vendor) (*hvs.Meta, error) {
	log.Trace("flavor/util/platform_flavor_util:GetMetaSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetMetaSectionDetails() Leaving")

	var meta hvs.Meta
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:GetMetaSectionDetails() failed to create new UUID")
	}
	// Set UUID
	meta.ID = newUuid
	meta.Vendor = vendor

	var biosName string
	var biosVersion string
	var osName string
	var osVersion string
	var vmmName string
	var vmmVersion string

	// Set Description
	var description = make(map[string]interface{})

	if hostDetails != nil {
		biosName = strings.TrimSpace(hostDetails.BiosName)
		biosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		description[hvs.TbootInstalled] = &hostDetails.TbootInstalled
		vmmName = strings.TrimSpace(hostDetails.VMMName)
		vmmVersion = strings.TrimSpace(hostDetails.VMMVersion)
		osName = strings.TrimSpace(hostDetails.OSName)
		osVersion = strings.TrimSpace(hostDetails.OSVersion)
		description[hvs.TpmVersion] = strings.TrimSpace(hostDetails.HardwareFeatures.TPM.Meta.TPMVersion)
	}

	switch flavorPartName {
	case hvs.FlavorPartPlatform:
		var features = pfutil.getSupportedHardwareFeatures(hostDetails)
		description[hvs.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), biosName,
			biosVersion, strings.Join(features, "_"), pfutil.getCurrentTimeStamp())
		description[hvs.BiosName] = biosName
		description[hvs.BiosVersion] = biosVersion
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description[hvs.Source] = strings.TrimSpace(hostDetails.HostName)
		}
	case hvs.FlavorPartOs:
		description[hvs.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), osName, osVersion,
			vmmName, vmmVersion, pfutil.getCurrentTimeStamp())
		description[hvs.OsName] = osName
		description[hvs.OsVersion] = osVersion
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		if hostDetails != nil && hostDetails.HostName != "" {
			description[hvs.Source] = strings.TrimSpace(hostDetails.HostName)
		}
		if vmmName != "" {
			description[hvs.VmmName] = strings.TrimSpace(vmmName)
		}
		if vmmVersion != "" {
			description[hvs.VmmVersion] = strings.TrimSpace(vmmVersion)
		}

	case hvs.FlavorPartSoftware:
		var measurements taModel.Measurement
		err := xml.Unmarshal([]byte(xmlMeasurement), &measurements)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed to parse XML measurements in Software Flavor: %s", err.Error())
		}
		description[hvs.Label] = measurements.Label
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		// set DigestAlgo to SHA384
		switch strings.ToUpper(measurements.DigestAlg) {
		case crypt.SHA384().Name:
			description[hvs.DigestAlgorithm] = crypt.SHA384().Name
		default:
			return nil, errors.Errorf("invalid Digest Algorithm in measurement XML")
		}
		meta.ID, err = uuid.Parse(measurements.Uuid)
		if err != nil {
			// if Software UUID is empty, we generate a new UUID and use it
			newUuid, err := uuid.NewRandom()
			if err != nil {
				return nil, errors.Wrap(err, "failed to create new UUID")
			}
			meta.ID = newUuid
		}
		meta.Schema = pfutil.getSchema()

	case hvs.FlavorPartAssetTag:
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		if hostDetails != nil {
			hwuuid, err := uuid.Parse(hostDetails.HardwareUUID)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			}
			description[hvs.HardwareUUID] = hwuuid.String()

			if hostDetails.HostName != "" {
				description[hvs.Source] = strings.TrimSpace(hostDetails.HostName)
			}
		} else if tagCertificate != nil {
			hwuuid, err := uuid.Parse(tagCertificate.Subject)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			} else {
				description[hvs.HardwareUUID] = hwuuid.String()
			}
		}
		description[hvs.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), description[hvs.HardwareUUID].(string), pfutil.getCurrentTimeStamp())

	case hvs.FlavorPartHostUnique:
		if hostDetails != nil {
			if hostDetails.HostName != "" {
				description[hvs.Source] = strings.TrimSpace(hostDetails.HostName)
			}
			hwuuid, err := uuid.Parse(hostDetails.HardwareUUID)
			if err != nil {
				return nil, errors.Wrapf(err, "Invalid Hardware UUID for %s FlavorPart", flavorPartName)
			}
			description[hvs.HardwareUUID] = hwuuid.String()
		}
		description[hvs.BiosName] = biosName
		description[hvs.BiosVersion] = biosVersion
		description[hvs.OsName] = osName
		description[hvs.OsVersion] = osVersion
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		description[hvs.Label] = pfutil.getLabelFromDetails(meta.Vendor.String(), description[hvs.HardwareUUID].(string), pfutil.getCurrentTimeStamp())
	case hvs.FlavorPartIma:
		description[hvs.FlavorPartDescription] = flavorPartName.String()
		description[hvs.Label] = constants.IMA
	default:
		return nil, errors.Errorf("Invalid FlavorPart %s", flavorPartName.String())
	}
	meta.Description = description

	return &meta, nil
}

// GetBiosSectionDetails populate the BIOS field details in Flavor
func (pfutil PlatformFlavorUtil) GetBiosSectionDetails(hostDetails *taModel.HostInfo) *hvs.Bios {
	log.Trace("flavor/util/platform_flavor_util:GetBiosSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetBiosSectionDetails() Leaving")

	var bios hvs.Bios
	if hostDetails != nil {
		bios.BiosName = strings.TrimSpace(hostDetails.BiosName)
		bios.BiosVersion = strings.TrimSpace(hostDetails.BiosVersion)
		return &bios
	}
	return nil
}

// getSchema sets the schema for the Meta struct in the flavor
func (pfutil PlatformFlavorUtil) getSchema() *hvs.Schema {
	log.Trace("flavor/util/platform_flavor_util:getSchema() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getSchema() Leaving")

	var schema hvs.Schema
	schema.Uri = constants.IslMeasurementSchema
	return &schema
}

// getHardwareSectionDetails extracts the host Hardware details from the manifest
func (pfutil PlatformFlavorUtil) GetHardwareSectionDetails(hostManifest *hvs.HostManifest) *hvs.Hardware {
	log.Trace("flavor/util/platform_flavor_util:GetHardwareSectionDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetHardwareSectionDetails() Leaving")

	var hardware hvs.Hardware
	var feature hvs.Feature

	hostInfo := hostManifest.HostInfo

	// Extract Processor Info
	hardware.ProcessorInfo = strings.TrimSpace(hostInfo.ProcessorInfo)
	hardware.ProcessorFlags = strings.TrimSpace(hostInfo.ProcessorFlags)

	// Set TPM Feature presence
	tpm := &hvs.TPM{}
	tpm.Enabled = hostInfo.HardwareFeatures.TPM.Enabled

	tpm.Meta.TPMVersion = hostInfo.HardwareFeatures.TPM.Meta.TPMVersion
	// populate tpm.Pcrbanks by checking the contents of PcrManifest
	if hostManifest.PcrManifest.Sha1Pcrs != nil && len(hostManifest.PcrManifest.Sha1Pcrs) > 0 {
		tpm.Meta.PCRBanks = append(tpm.Meta.PCRBanks, string(hvs.SHA1))
	}
	if hostManifest.PcrManifest.Sha256Pcrs != nil && len(hostManifest.PcrManifest.Sha256Pcrs) > 0 {
		tpm.Meta.PCRBanks = append(tpm.Meta.PCRBanks, string(hvs.SHA256))
	}
	if hostManifest.PcrManifest.Sha384Pcrs != nil && len(hostManifest.PcrManifest.Sha384Pcrs) > 0 {
		tpm.Meta.PCRBanks = append(tpm.Meta.PCRBanks, string(hvs.SHA384))
	}
	feature.TPM = tpm

	if hostInfo.HardwareFeatures.TXT != nil {
		txt := &hvs.HardwareFeature{}
		txt.Enabled = hostInfo.HardwareFeatures.TXT.Enabled
		feature.TXT = txt
	}

	// set CBNT
	if hostInfo.HardwareFeatures.CBNT != nil {
		cbnt := &hvs.CBNT{}
		cbnt.Enabled = hostInfo.HardwareFeatures.CBNT.Enabled
		cbnt.Meta.Profile = hostInfo.HardwareFeatures.CBNT.Meta.Profile
		cbnt.Meta.MSR = hostInfo.HardwareFeatures.CBNT.Meta.MSR
		feature.CBNT = cbnt
	}

	// and UEFI state
	if hostInfo.HardwareFeatures.UEFI != nil {
		uefi := &hvs.UEFI{}
		uefi.Enabled = hostInfo.HardwareFeatures.UEFI.Enabled
		uefi.Meta.SecureBootEnabled = hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled
		feature.UEFI = uefi
	}

	// Set BMC Feature presence
	if hostInfo.HardwareFeatures.BMC != nil {
		bmc := &hvs.HardwareFeature{}
		bmc.Enabled = hostInfo.HardwareFeatures.BMC.Enabled
		feature.BMC = bmc
	}

	// Set PFR Feature presence
	if hostInfo.HardwareFeatures.PFR != nil {
		pfr := &taModel.HardwareFeature{}
		pfr.Enabled = hostInfo.HardwareFeatures.PFR.Enabled
		feature.PFR = pfr
	}

	hardware.Feature = &feature
	return &hardware
}

// GetPcrDetails extracts Pcr values and Event Logs from the HostManifest/PcrManifest and  returns
// in a format suitable for inserting into the flavor
func (pfutil PlatformFlavorUtil) GetPcrDetails(pcrManifest hvs.PcrManifest, pcrList map[hvs.PcrIndex]hvs.PcrListRules) []hvs.FlavorPcrs {
	log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetPcrDetails() Leaving")

	var pcrCollection []hvs.FlavorPcrs

	// pull out the logs for the required PCRs from both banks
	for index, rules := range pcrList {
		pI := index
		var pcrInfo *hvs.HostManifestPcrs
		var bank string
		// based on the bank priority get the value of PCR index from host manifest
		for _, bank = range rules.PcrBank {
			pcrInfo, _ = pcrManifest.GetPcrValue(hvs.SHAAlgorithm(bank), pI)
			if pcrInfo != nil && pcrInfo.Value != "" {
				break
			}
		}

		if pcrInfo != nil {
			var currPcrEx hvs.FlavorPcrs
			currPcrEx.Pcr.Index = int(index)
			currPcrEx.Pcr.Bank = bank
			currPcrEx.Measurement = pcrInfo.Value
			if rules.PcrMatches {
				currPcrEx.PCRMatches = true
			}

			// Populate Event log value
			var eventLogEqualEvents []hvs.EventLog
			manifestPcrEventLogs, err := pcrManifest.GetEventLogCriteria(hvs.SHAAlgorithm(bank), pI)

			// check if returned logset from PCR is nil
			if manifestPcrEventLogs != nil && err == nil {

				// Convert EventLog to flavor format
				for _, manifestEventLog := range manifestPcrEventLogs {
					if len(manifestEventLog.Tags) == 0 {
						if rules.PcrEquals.IsPcrEquals {
							eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
						}
					}
					presentInExcludeTag := false
					for _, tag := range manifestEventLog.Tags {
						if _, ok := rules.PcrIncludes[tag]; ok {
							currPcrEx.EventlogIncludes = append(currPcrEx.EventlogIncludes, manifestEventLog)
							break
						} else if rules.PcrEquals.IsPcrEquals {
							if _, ok := rules.PcrEquals.ExcludingTags[tag]; ok {
								presentInExcludeTag = true
								break
							}
						}
					}
					if !presentInExcludeTag {
						eventLogEqualEvents = append(eventLogEqualEvents, manifestEventLog)
					}
				}
				if rules.PcrEquals.IsPcrEquals {
					var EventLogExcludes []string
					for excludeTag := range rules.PcrEquals.ExcludingTags {
						EventLogExcludes = append(EventLogExcludes, excludeTag)
					}
					currPcrEx.EventlogEqual = &hvs.EventLogEqual{
						Events:      eventLogEqualEvents,
						ExcludeTags: EventLogExcludes,
					}
				}
			}
			pcrCollection = append(pcrCollection, currPcrEx)
		}
	}

	// return map for flavor to use
	return pcrCollection
}

// GetExternalConfigurationDetails extracts the External field for the flavor from the HostManifest
func (pfutil PlatformFlavorUtil) GetExternalConfigurationDetails(tagCertificate *hvs.X509AttributeCertificate) (*hvs.External, error) {
	log.Trace("flavor/util/platform_flavor_util:GetExternalConfigurationDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetExternalConfigurationDetails() Leaving")

	var externalconfiguration hvs.External
	var assetTag hvs.AssetTag

	if tagCertificate == nil {
		return nil, errors.Errorf("Specified tagcertificate is not valid")
	}
	assetTag.TagCertificate = *tagCertificate
	externalconfiguration.AssetTag = assetTag
	return &externalconfiguration, nil
}

// getSupportedHardwareFeatures returns a list of hardware features supported by the host from its HostInfo
func (pfutil PlatformFlavorUtil) getSupportedHardwareFeatures(hostDetails *taModel.HostInfo) []string {
	log.Trace("flavor/util/platform_flavor_util:getSupportedHardwareFeatures() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getSupportedHardwareFeatures() Leaving")

	var features []string
	if hostDetails.HardwareFeatures.CBNT != nil && hostDetails.HardwareFeatures.CBNT.Enabled {
		features = append(features, constants.Cbnt)
		features = append(features, hostDetails.HardwareFeatures.CBNT.Meta.Profile)
	}

	if hostDetails.HardwareFeatures.TPM != nil && hostDetails.HardwareFeatures.TPM.Enabled {
		features = append(features, constants.Tpm)
	}

	if hostDetails.HardwareFeatures.TXT != nil && hostDetails.HardwareFeatures.TXT.Enabled {
		features = append(features, constants.Txt)
	}

	if hostDetails.HardwareFeatures.UEFI != nil && hostDetails.HardwareFeatures.UEFI.Enabled {
		features = append(features, constants.Uefi)
	}
	if hostDetails.HardwareFeatures.UEFI != nil && hostDetails.HardwareFeatures.UEFI.Meta.SecureBootEnabled {
		features = append(features, constants.SecureBootEnabled)
	}

	return features
}

// getLabelFromDetails generates a flavor label string by combining the details
//from separate fields into a single string separated by underscore
func (pfutil PlatformFlavorUtil) getLabelFromDetails(names ...string) string {
	log.Trace("flavor/util/platform_flavor_util:getLabelFromDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getLabelFromDetails() Leaving")

	var labels []string
	for _, s := range names {
		labels = append(labels, strings.Join(strings.Fields(s), ""))
	}
	return strings.Join(labels, "_")
}

// getCurrentTimeStamp generates the current time in the required format
func (pfutil PlatformFlavorUtil) getCurrentTimeStamp() string {
	log.Trace("flavor/util/platform_flavor_util:getCurrentTimeStamp() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getCurrentTimeStamp() Leaving")

	// Use magical reference date to specify the format
	return time.Now().Format(constants.FlavorWoTimestampFormat)
}

// getSignedFlavorList performs a bulk signing of a list of flavor strings and returns a list of SignedFlavors
func (pfutil PlatformFlavorUtil) GetSignedFlavorList(flavors []hvs.Flavor, flavorSigningPrivateKey *rsa.PrivateKey) ([]hvs.SignedFlavor, error) {
	log.Trace("flavor/util/platform_flavor_util:GetSignedFlavorList() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetSignedFlavorList() Leaving")

	var signedFlavors []hvs.SignedFlavor

	if flavors != nil {
		// loop through and sign each flavor
		for _, unsignedFlavor := range flavors {
			var sf *hvs.SignedFlavor
			sf, err := pfutil.GetSignedFlavor(&unsignedFlavor, flavorSigningPrivateKey)
			if err != nil {
				return nil, errors.Errorf("Error signing flavor collection: %s", err.Error())
			}
			signedFlavors = append(signedFlavors, *sf)
		}
	} else {
		return nil, errors.Errorf("empty flavors list provided")
	}

	return signedFlavors, nil
}

// GetSignedFlavor is used to sign the flavor
func (pfutil PlatformFlavorUtil) GetSignedFlavor(unsignedFlavor *hvs.Flavor, privateKey *rsa.PrivateKey) (*hvs.SignedFlavor, error) {
	log.Trace("flavor/util/platform_flavor_util:GetSignedFlavor() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetSignedFlavor() Leaving")

	if unsignedFlavor == nil {
		return nil, errors.New("GetSignedFlavor: Flavor content missing")
	}

	signedFlavor, err := hvs.NewSignedFlavor(unsignedFlavor, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "GetSignedFlavor: Error while marshalling signed flavor")
	}

	return signedFlavor, nil
}

// GetPcrRulesMap Helper function to calculate the list of PCRs for the flavor part specified based
// on the version of the TPM hardware.
func (pfutil PlatformFlavorUtil) GetPcrRulesMap(flavorPart hvs.FlavorPartName, flavorTemplates []hvs.FlavorTemplate) (map[hvs.PcrIndex]hvs.PcrListRules, error) {
	log.Trace("flavor/util/platform_flavor_util:getPcrRulesMap() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getPcrRulesMap() Leaving")

	pcrRulesForFlavorPart := make(map[hvs.PcrIndex]hvs.PcrListRules)
	var err error
	for _, flavorTemplate := range flavorTemplates {
		switch flavorPart {
		case hvs.FlavorPartPlatform:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.Platform, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for platform flavor")
			}
			break
		case hvs.FlavorPartOs:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.OS, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for os flavor")
			}
			break
		case hvs.FlavorPartHostUnique:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.HostUnique, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for host unique flavor")
			}
			break
		case hvs.FlavorPartIma:
			pcrRulesForFlavorPart, err = getPcrRulesForFlavorPart(flavorTemplate.FlavorParts.Ima, pcrRulesForFlavorPart)
			if err != nil {
				return nil, errors.Wrap(err, "flavor/util/platform_flavor_util:getPcrRulesMap() Error getting pcr rules for ima flavor")
			}
			break
		}
	}

	return pcrRulesForFlavorPart, nil
}

func getPcrRulesForFlavorPart(flavorPart *hvs.FlavorPart, pcrList map[hvs.PcrIndex]hvs.PcrListRules) (map[hvs.PcrIndex]hvs.PcrListRules, error) {
	log.Trace("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Leaving")

	if flavorPart == nil {
		return pcrList, nil
	}

	if pcrList == nil {
		pcrList = make(map[hvs.PcrIndex]hvs.PcrListRules)
	}

	for _, pcrRule := range flavorPart.PcrRules {
		var rulesList hvs.PcrListRules

		if rules, ok := pcrList[hvs.PcrIndex(pcrRule.Pcr.Index)]; ok {
			rulesList = rules
		}
		rulesList.PcrBank = pcrRule.Pcr.Bank
		if pcrRule.PcrMatches != nil && *pcrRule.PcrMatches {
			rulesList.PcrMatches = true
		}
		if rulesList.PcrIncludes != nil && pcrRule.EventlogEquals != nil {
			return nil, errors.New("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Error getting pcrList : Both event log equals and includes rule present for single pcr index/bank")
		}
		if pcrRule.EventlogEquals != nil {
			rulesList.PcrEquals.IsPcrEquals = true
			if pcrRule.EventlogEquals.ExcludingTags != nil {
				rulesList.PcrEquals.ExcludingTags = make(map[string]bool)
				for _, tags := range pcrRule.EventlogEquals.ExcludingTags {
					if _, ok := rulesList.PcrEquals.ExcludingTags[tags]; !ok {
						rulesList.PcrEquals.ExcludingTags[tags] = false
					}
				}
			}
		}

		if rulesList.PcrEquals.IsPcrEquals == true && pcrRule.EventlogIncludes != nil {
			return nil, errors.New("flavor/util/platform_flavor_util:getPcrRulesForFlavorPart() Error getting pcrList : Both event log equals and includes rule present for single pcr index/bank")
		}

		if pcrRule.EventlogIncludes != nil {
			rulesList.PcrIncludes = make(map[string]bool)
			for _, tags := range pcrRule.EventlogIncludes {
				if _, ok := rulesList.PcrIncludes[tags]; !ok {
					rulesList.PcrIncludes[tags] = true
				}
			}
		}
		pcrList[hvs.PcrIndex(pcrRule.Pcr.Index)] = rulesList
	}

	return pcrList, nil
}

func (pfutil PlatformFlavorUtil) GetImaDetails(imaLogs hvs.ImaLogs) hvs.Ima {
	log.Trace("flavor/util/platform_flavor_util:GetImaDetails() Entering")
	defer log.Trace("flavor/util/platform_flavor_util:GetImaDetails() Leaving")

	var ima hvs.Ima
	ima.Measurements = imaLogs.Measurements

	return ima
}
