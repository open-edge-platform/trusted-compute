/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"crypto"
	"encoding/hex"
	"encoding/xml"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	cf "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/util"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

// LinuxPlatformFlavor is used to generate various Flavors for a Intel-based Linux host
type HostPlatformFlavor struct {
	HostManifest    *hvs.HostManifest             `json:"host_manifest"`
	HostInfo        *taModel.HostInfo             `json:"host_info"`
	TagCertificate  *hvs.X509AttributeCertificate `json:"tag_certificate"`
	FlavorTemplates []hvs.FlavorTemplate
}

var pfutil util.PlatformFlavorUtil
var sfutil util.SoftwareFlavorUtil

// NewHostPlatformFlavor returns an instance of LinuxPlatformFlavor
func NewHostPlatformFlavor(hostReport *hvs.HostManifest, tagCertificate *hvs.X509AttributeCertificate, flavorTemplates []hvs.FlavorTemplate) PlatformFlavor {
	log.Trace("flavor/types/host_platform_flavor:NewHostPlatformFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:NewHostPlatformFlavor() Leaving")

	return HostPlatformFlavor{
		HostManifest:    hostReport,
		HostInfo:        &hostReport.HostInfo,
		TagCertificate:  tagCertificate,
		FlavorTemplates: flavorTemplates,
	}
}

// GetFlavorPartRaw extracts the details of the flavor part requested by the
// caller from the host report used during the creation of the PlatformFlavor instance
func (pf HostPlatformFlavor) GetFlavorPartRaw(name hvs.FlavorPartName) ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:GetFlavorPartRaw() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:GetFlavorPartRaw() Leaving")

	switch name {
	case hvs.FlavorPartPlatform:
		return pf.getPlatformFlavor()
	case hvs.FlavorPartOs:
		return pf.getOsFlavor()
	case hvs.FlavorPartAssetTag:
		return pf.getAssetTagFlavor()
	case hvs.FlavorPartHostUnique:
		return pf.getHostUniqueFlavor()
	case hvs.FlavorPartSoftware:
		if pf.HostManifest.HostInfo.OSType == taModel.OsTypeLinux {
			return pf.getDefaultSoftwareFlavor()
		} else {
			return nil, cf.UNKNOWN_FLAVOR_PART()
		}
	case hvs.FlavorPartIma:
		return pf.getImaFlavor()
	}
	return nil, cf.UNKNOWN_FLAVOR_PART()
}

// GetFlavorPartNames retrieves the list of flavor parts that can be obtained using the GetFlavorPartRaw function
func (pf HostPlatformFlavor) GetFlavorPartNames() ([]hvs.FlavorPartName, error) {
	log.Trace("flavor/types/host_platform_flavor:GetFlavorPartNames() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:GetFlavorPartNames() Leaving")

	if strings.ToUpper(pf.HostManifest.HostInfo.OSName) == constants.OsLinux {
		return []hvs.FlavorPartName{
			hvs.FlavorPartPlatform, hvs.FlavorPartOs,
			hvs.FlavorPartHostUnique, hvs.FlavorPartSoftware,
			hvs.FlavorPartAssetTag, hvs.FlavorPartIma}, nil
	} else {
		return []hvs.FlavorPartName{
			hvs.FlavorPartPlatform, hvs.FlavorPartOs,
			hvs.FlavorPartHostUnique, hvs.FlavorPartAssetTag}, nil
	}
}

func isCbntMeasureProfile(cbnt *taModel.CBNT) bool {
	log.Trace("flavor/types/host_platform_flavor:isCbntMeasureProfile() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:isCbntMeasureProfile() Leaving")

	if cbnt != nil {
		return cbnt.Enabled && cbnt.Meta.Profile == cf.BootGuardProfile5().Name
	}
	return false
}

// getPlatformFlavor returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the PLATFORM trust of a host
func (pf HostPlatformFlavor) getPlatformFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getPlatformFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getPlatformFlavor() Leaving")

	var errorMessage = "Error during creation of PLATFORM flavor"
	platformPcrs, err := pfutil.GetPcrRulesMap(hvs.FlavorPartPlatform, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getPlatformFlavor() %s Failure in getting pcrlist", errorMessage)
	}

	var allPcrDetails = pfutil.GetPcrDetails(pf.HostManifest.PcrManifest, platformPcrs)

	newMeta, err := pfutil.GetMetaSectionDetails(pf.HostInfo, pf.TagCertificate, "", hvs.FlavorPartPlatform, pf.getVendorName())
	if err != nil {
		return nil, errors.Wrapf(err, errorMessage, "%s - failure in Meta section details")
	}
	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(hvs.FlavorPartPlatform, newMeta, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getPlatformFlavor() %s failure in Updating Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(pf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("flavor/types/host_platform_flavor:getPlatformFlavor() %s failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor() New Bios Section: %v", *newBios)

	newHW := pfutil.GetHardwareSectionDetails(pf.HostManifest)
	if newHW == nil {
		return nil, errors.Errorf("flavor/types/host_platform_flavor:getPlatformFlavor() %s failure in Hardware section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor() New Hardware Section: %v", *newHW)

	// Assemble the Platform Flavor
	platformFlavor := hvs.NewFlavor(newMeta, newBios, newHW, allPcrDetails, nil, nil, nil)

	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor()  New PlatformFlavor: %v", platformFlavor)

	return []hvs.Flavor{*platformFlavor}, nil
}

// getOsFlavor Returns a json document having all the good known PCR values and
// corresponding event logs that can be used for evaluating the OS Trust of a host
func (pf HostPlatformFlavor) getOsFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getOsFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getOsFlavor() Leaving")

	var errorMessage = "Error during creation of OS flavor"
	osPcrs, err := pfutil.GetPcrRulesMap(hvs.FlavorPartOs, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getOsFlavor() %s Failure in getting pcrlist", errorMessage)
	}

	var allPcrDetails = pfutil.GetPcrDetails(pf.HostManifest.PcrManifest, osPcrs)

	newMeta, err := pfutil.GetMetaSectionDetails(pf.HostInfo, pf.TagCertificate, "", hvs.FlavorPartOs, pf.getVendorName())
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getOsFlavor() %s Failure in Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(hvs.FlavorPartOs, newMeta, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getOsFlavor() %s failure in Updating Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getOsFlavor() New Meta Section: %v", *newMeta)
	newBios := pfutil.GetBiosSectionDetails(pf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("flavor/types/host_platform_flavor:getOsFlavor() %s Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getOsFlavor() New Bios Section: %v", *newBios)

	// Assemble the OS Flavor
	osFlavor := hvs.NewFlavor(newMeta, newBios, nil, allPcrDetails, nil, nil, nil)

	log.Debugf("flavor/types/host_platform_flavor:getOSFlavor()  New OS Flavor: %v", osFlavor)

	return []hvs.Flavor{*osFlavor}, nil
}

// getHostUniqueFlavor Returns a json document having all the good known PCR values and corresponding event logs that
// can be used for evaluating the unique part of the PCR configurations of a host. These include PCRs/modules getting
// extended to PCRs that would vary from host to host.
func (pf HostPlatformFlavor) getHostUniqueFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getHostUniqueFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getHostUniqueFlavor() Leaving")

	var errorMessage = "Error during creation of HOST_UNIQUE flavor"
	var err error
	hostUniquePcrs, err := pfutil.GetPcrRulesMap(hvs.FlavorPartHostUnique, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getHostUniqueFlavor() %s Failure in getting pcrlist", errorMessage)
	}

	var allPcrDetails = pfutil.GetPcrDetails(pf.HostManifest.PcrManifest, hostUniquePcrs)

	newMeta, err := pfutil.GetMetaSectionDetails(pf.HostInfo, pf.TagCertificate, "", hvs.FlavorPartHostUnique, pf.getVendorName())
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getHostUniqueFlavor() %s Failure in Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getHostUniqueFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(hvs.FlavorPartHostUnique, newMeta, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getHostUniqueFlavor() %s failure in Updating Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getPlatformFlavor() New Meta Section: %v", *newMeta)

	newBios := pfutil.GetBiosSectionDetails(pf.HostInfo)
	if newBios == nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getHostUniqueFlavor() %s Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getHostUniqueFlavor() New Bios Section: %v", *newBios)

	// Assemble the Host Unique Flavor
	hostUniqueFlavor := hvs.NewFlavor(newMeta, newBios, nil, allPcrDetails, nil, nil, nil)

	log.Debugf("flavor/types/host_platform_flavor:getHostUniqueFlavor() New Host unique flavor: %v", hostUniqueFlavor)

	return []hvs.Flavor{*hostUniqueFlavor}, nil
}

func (pf HostPlatformFlavor) getImaFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getImaFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getImaFlavor() Leaving")

	var errorMessage = "Error during creation of IMA flavor"
	var err error

	if pf.HostManifest.ImaLogs == nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getImaFlavor() %s No imalogs present in host manifest", errorMessage)
	}

	imaPcrs, err := pfutil.GetPcrRulesMap(hvs.FlavorPartIma, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getImaFlavor() %s Failure in getting pcrlist", errorMessage)
	}

	var allPcrDetails = pfutil.GetPcrDetails(pf.HostManifest.PcrManifest, imaPcrs)

	var allImaDetails = pfutil.GetImaDetails(*pf.HostManifest.ImaLogs)

	newMeta, err := pfutil.GetMetaSectionDetails(nil, nil, "", hvs.FlavorPartIma, pf.getVendorName())
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getImaFlavor() %s Failure in Meta section details", errorMessage)
	}
	newMeta.Description[hvs.DigestAlgorithm] = pf.HostManifest.ImaLogs.Pcr.Bank
	log.Debugf("flavor/types/host_platform_flavor:getImaFlavor() New Meta Section: %v", *newMeta)

	newMeta = UpdateMetaSectionDetails(hvs.FlavorPartIma, newMeta, pf.FlavorTemplates)
	if err != nil {
		return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getImaFlavor() %s failure in Updating Meta section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getImaFlavor() New Meta Section: %v", *newMeta)

	// Assemble the Ima Flavor
	imaFlavor := hvs.NewFlavor(newMeta, nil, nil, allPcrDetails, nil, nil, &allImaDetails)

	log.Debugf("flavor/types/host_platform_flavor:getImaFlavor() New Ima flavor: %v", imaFlavor)

	return []hvs.Flavor{*imaFlavor}, nil
}

// getAssetTagFlavor Retrieves the asset tag part of the flavor including the certificate and all the key-value pairs
// that are part of the certificate.
func (pf HostPlatformFlavor) getAssetTagFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getAssetTagFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getAssetTagFlavor() Leaving")

	var errorMessage = "Error during creation of ASSET_TAG flavor"
	var err error
	var tagCertificateHash []byte
	var expectedPcrValue string
	var pcrDetails []hvs.FlavorPcrs
	if pf.TagCertificate == nil {
		return nil, errors.Errorf("%s - %s", errorMessage, cf.FLAVOR_PART_CANNOT_BE_SUPPORTED().Message)
	}

	if strings.ToUpper(pf.HostManifest.HostInfo.OSName) == constants.OsVMware {
		// calculate the expected PCR 22 value based on tag certificate hash event
		tagCertificateHash, err = crypt.GetHashData(pf.TagCertificate.Encoded, crypto.SHA1)
		if err != nil {
			return nil, errors.Wrapf(err, errorMessage, "%s Failure in evaluating certificate digest")
		}

		//Vmware supports only SHA1 value to be pushed and measure, hence use SHA1 bank here
		expectedEventLogEntry := hvs.TpmEventLog{
			Pcr: hvs.Pcr{
				Index: constants.PCR22,
				Bank:  constants.SHA1,
			},
			TpmEvent: []hvs.EventLog{
				{
					Measurement: hex.EncodeToString(tagCertificateHash),
				},
			},
		}

		expectedPcrValue, err = expectedEventLogEntry.Replay()
		if err != nil {
			return nil, errors.Wrapf(err, errorMessage, "%s Failure in evaluating PCR22 value")
		}

		pcrDetails = []hvs.FlavorPcrs{
			{
				Pcr: hvs.Pcr{
					Index: constants.PCR22,
					Bank:  constants.SHA1,
				},
				Measurement: expectedPcrValue,
				PCRMatches:  true,
			},
		}
	}

	// create meta section details
	newMeta, err := pfutil.GetMetaSectionDetails(pf.HostInfo, pf.TagCertificate, "", hvs.FlavorPartAssetTag, pf.getVendorName())
	if err != nil {
		return nil, errors.Wrapf(err, errorMessage, "%s Failure in Meta section details")
	}
	log.Debugf("flavor/types/host_platform_flavor:getAssetTagFlavor() New Meta Section: %v", *newMeta)

	// create bios section details
	newBios := pfutil.GetBiosSectionDetails(pf.HostInfo)
	if newBios == nil {
		return nil, errors.Errorf("%s - Failure in Bios section details", errorMessage)
	}
	log.Debugf("flavor/types/host_platform_flavor:getAssetTagFlavor() New Bios Section: %v", *newBios)

	// create external section details
	newExt, err := pfutil.GetExternalConfigurationDetails(pf.TagCertificate)
	if err != nil {
		return nil, errors.Wrapf(err, errorMessage, "%s Failure in External configuration section details")
	}
	log.Debugf("flavor/types/host_platform_flavor:getAssetTagFlavor() New External Section: %v", *newExt)

	// Assemble the Asset Tag Flavor
	var assetTagFlavor *hvs.Flavor
	if strings.ToUpper(pf.HostManifest.HostInfo.OSName) == constants.OsLinux {
		assetTagFlavor = hvs.NewFlavor(newMeta, newBios, nil, nil, newExt, nil, nil)
	} else {
		assetTagFlavor = hvs.NewFlavor(newMeta, newBios, nil, pcrDetails, newExt, nil, nil)
	}

	log.Debugf("flavor/types/host_platform_flavor:getAssetTagFlavor() New Asset Tag Flavor: %v", assetTagFlavor)

	return []hvs.Flavor{*assetTagFlavor}, nil
}

// getDefaultSoftwareFlavor Method to create a software flavor. This method would create a software flavor that would
// include all the measurements provided from host.
func (pf HostPlatformFlavor) getDefaultSoftwareFlavor() ([]hvs.Flavor, error) {
	log.Trace("flavor/types/host_platform_flavor:getDefaultSoftwareFlavor() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getDefaultSoftwareFlavor() Leaving")

	var softwareFlavors []hvs.Flavor
	var errorMessage = cf.SOFTWARE_FLAVOR_CANNOT_BE_CREATED().Message

	if pf.HostManifest != nil && pf.HostManifest.MeasurementXmls != nil {
		measurementXmls, err := pf.getDefaultMeasurement()
		if err != nil {
			return nil, errors.Wrapf(err, errorMessage)
		}

		for _, measurementXml := range measurementXmls {
			var softwareFlavor = NewSoftwareFlavor(measurementXml)
			swFlavor, err := softwareFlavor.GetSoftwareFlavor()
			if err != nil {
				return nil, err
			}
			softwareFlavors = append(softwareFlavors, *swFlavor)
		}
	}
	log.Debugf("flavor/types/host_platform_flavor:getDefaultSoftwareFlavor() New Software Flavor: %v", softwareFlavors)
	return softwareFlavors, nil
}

// getDefaultMeasurement returns a default set of measurements for the Platform Flavor
func (pf HostPlatformFlavor) getDefaultMeasurement() ([]string, error) {
	log.Trace("flavor/types/host_platform_flavor:getDefaultMeasurement() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:getDefaultMeasurement() Leaving")

	var measurementXmlCollection []string
	var err error

	for _, measurementXML := range pf.HostManifest.MeasurementXmls {
		var measurement taModel.Measurement
		err = xml.Unmarshal([]byte(measurementXML), &measurement)
		if err != nil {
			return nil, errors.Wrapf(err, "flavor/types/host_platform_flavor:getDefaultMeasurement() Error unmarshalling measurement XML: %s", err.Error())
		}
		if strings.Contains(measurement.Label, constants.DefaultSoftwareFlavorPrefix) ||
			strings.Contains(measurement.Label, constants.DefaultWorkloadFlavorPrefix) {
			measurementXmlCollection = append(measurementXmlCollection, measurementXML)
			log.Debugf("flavor/types/host_platform_flavor:getDefaultMeasurement() Measurement XML: %s", measurementXML)
		}
	}
	return measurementXmlCollection, nil
}

// UpdateMetaSectionDetails This method is used to update the meta section in flavor part
func UpdateMetaSectionDetails(flavorPart hvs.FlavorPartName, newMeta *hvs.Meta, flavorTemplates []hvs.FlavorTemplate) *hvs.Meta {
	log.Trace("flavor/types/host_platform_flavor:UpdateMetaSectionDetails() Entering")
	defer log.Trace("flavor/types/host_platform_flavor:UpdateMetaSectionDetails() Leaving")

	var flavorTemplateIDList []uuid.UUID
	for _, flavorTemplate := range flavorTemplates {
		flavorTemplateIDList = append(flavorTemplateIDList, flavorTemplate.ID)
		var flavor *hvs.FlavorPart
		switch flavorPart {
		case hvs.FlavorPartPlatform:
			flavor = flavorTemplate.FlavorParts.Platform
		case hvs.FlavorPartOs:
			flavor = flavorTemplate.FlavorParts.OS
		case hvs.FlavorPartHostUnique:
			flavor = flavorTemplate.FlavorParts.HostUnique
		case hvs.FlavorPartIma:
			flavor = flavorTemplate.FlavorParts.Ima
		}

		// Update the meta section in the flavor part with the meta section provided in the flavor template
		if flavor != nil {
			for key, value := range flavor.Meta {
				newMeta.Description[key] = value
			}
		}
	}
	newMeta.Description["flavor_template_ids"] = flavorTemplateIDList
	return newMeta
}

//getVendorName This method is used to get the vendor name
func (pf HostPlatformFlavor) getVendorName() hcConstants.Vendor {
	var vendorName hcConstants.Vendor
	if strings.ToLower(pf.HostManifest.HostInfo.OSType) == taModel.OsTypeLinux {
		vendorName = hcConstants.VendorIntel
	} else {
		vendorName = hcConstants.VendorVMware
	}
	return vendorName
}
