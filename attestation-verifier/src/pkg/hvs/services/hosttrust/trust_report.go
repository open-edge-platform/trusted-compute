/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"encoding/xml"
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hosttrust/rules"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// FlavorVerify.java: 529
// renamed to CreateFlavorGroupReport and made it a receiver function since we need certificates
// from the config
func (v *Verifier) CreateFlavorGroupReport(hostId uuid.UUID, reqs flvGrpHostTrustReqs,
	hostData *hvs.HostManifest,
	trustCache hostTrustCache) (hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() Leaving")

	reqAndDefFlavorTypes := reqs.DefinedAndRequiredFlavorTypes
	latestReqAndDefFlavorTypes := reqs.GetLatestFlavorTypeMap()

	if trustCache.isTrustCacheEmpty() {
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() No results found in Trust Cache")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, latestReqAndDefFlavorTypes)
	}

	missingRequiredFlavorPartsWithLatest := getMissingRequiredFlavorPartsWithLatest(hostId, reqs, reqAndDefFlavorTypes, trustCache.trustReport)
	if len(missingRequiredFlavorPartsWithLatest) != 0 {
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() No results found for Required FlavorPartsWithLatest policy")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, missingRequiredFlavorPartsWithLatest)
	}

	ruleAllOfFlavors := rules.NewAllOfFlavors(reqs.AllOfFlavors, reqs.getAllOfMarkers(), v.SkipFlavorSignatureVerification, v.FlavorVerifier.GetVerifierCerts())
	if areAllOfFlavorsMissingInCachedTrustReport(trustCache.trustReport, ruleAllOfFlavors) {
		defaultLog.Trace("hosttrust/trust_report:CreateFlavorGroupReport() All Of Flavors Missing In Cached TrustReport")
		return v.createTrustReport(hostId, hostData, reqs, trustCache, latestReqAndDefFlavorTypes)
	}

	return trustCache.trustReport, nil
}

func areAllOfFlavorsMissingInCachedTrustReport(cachedTrustReport hvs.TrustReport, ruleAllOfFlavors rules.AllOfFlavors) bool {
	return len(ruleAllOfFlavors.AllOfFlavors) != 0 && !ruleAllOfFlavors.CheckAllOfFlavorsExist(&cachedTrustReport)
}

func getMissingRequiredFlavorPartsWithLatest(hostId uuid.UUID, reqs flvGrpHostTrustReqs, reqAndDefFlavorTypes map[hvs.FlavorPartName]bool, cachedTrustReport hvs.TrustReport) map[hvs.FlavorPartName]bool {
	defaultLog.Trace("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Leaving")
	missingRequiredFlavorPartsWithLatest := make(map[hvs.FlavorPartName]bool)
	for flavorPart := range reqAndDefFlavorTypes {
		defaultLog.Debugf("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Checking if required flavor type %s for host %s is missing", flavorPart.String(), hostId.String())
		if areRequiredFlavorsMissing(cachedTrustReport, flavorPart) {
			defaultLog.Debugf("hosttrust/trust_report:getMissingRequiredFlavorPartsWithLatest() Required flavor type %s for host %s is missing", flavorPart.String(), hostId.String())
			matchPolicyMissing := getMatchPolicy(reqs.FlavorMatchPolicies, flavorPart)
			if matchPolicyMissing != nil && matchPolicyMissing.MatchType == hvs.MatchTypeLatest {
				missingRequiredFlavorPartsWithLatest[flavorPart] = true
			} else {
				missingRequiredFlavorPartsWithLatest[flavorPart] = false
			}
		}
	}
	return missingRequiredFlavorPartsWithLatest
}

func areRequiredFlavorsMissing(cachedTrustReport hvs.TrustReport, flavorPart hvs.FlavorPartName) bool {
	return cachedTrustReport.GetResultsForMarker(flavorPart.String()) == nil && len(cachedTrustReport.GetResultsForMarker(flavorPart.String())) == 0
}

// FlavorVerify.java: 529
func (v *Verifier) createTrustReport(hostId uuid.UUID, hostData *hvs.HostManifest, reqs flvGrpHostTrustReqs, trustCache hostTrustCache, latestReqAndDefFlavorTypes map[hvs.FlavorPartName]bool) (hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:createTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:createTrustReport() Leaving")

	flavorParts := []hvs.FlavorPartName{}
	for flavorPart := range latestReqAndDefFlavorTypes {
		flavorParts = append(flavorParts, flavorPart)
	}

	hostManifestMap, err := getHostManifestMap(hostData, flavorParts)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error while creating host manifest map")
	}
	flavorsToVerify, err := v.findFlavors(reqs.FlavorGroupId, latestReqAndDefFlavorTypes, hostManifestMap)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error while finding flavors")
	}
	trustReport, err := v.verifyFlavors(hostId, flavorsToVerify, hostData, reqs)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error while verifying flavors")
	}
	if !trustCache.isTrustCacheEmpty() {
		trustReport.AddResults(trustCache.trustReport.Results)
	}

	for flavorPart := range reqs.DefinedAndRequiredFlavorTypes {
		rule := rules.NewRequiredFlavorTypeExists(flavorPart)
		trustReport = rule.Apply(*trustReport)
	}

	ruleAllOfFlavors := rules.NewAllOfFlavors(reqs.AllOfFlavors, reqs.getAllOfMarkers(), v.SkipFlavorSignatureVerification, v.FlavorVerifier.GetVerifierCerts())

	trustReport, err = ruleAllOfFlavors.AddFaults(trustReport)
	if err != nil {
		return hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:createTrustReport() Error applying ruleAllOfFlavors")
	}
	return *trustReport, nil
}

func getMatchPolicy(flvMatchPolicies hvs.FlavorMatchPolicies, part hvs.FlavorPartName) *hvs.MatchPolicy {
	defaultLog.Trace("hosttrust/trust_report:getMatchPolicy() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMatchPolicy() Leaving")

	for _, policy := range flvMatchPolicies {
		if policy.FlavorPart == part {
			return &policy.MatchPolicy
		}
	}
	return nil
}

// structure to hold the Flavor Report that is obtained from the verifier library
type flavorReport struct {
	id         uuid.UUID
	flavorPart hvs.FlavorPartName
	report     *hvs.TrustReport
	faultCount int
}

// FlavorVerify.java: 405
func (v *Verifier) verifyFlavors(hostID uuid.UUID, flavors []hvs.SignedFlavor, hostData *hvs.HostManifest, hostTrustReqs flvGrpHostTrustReqs) (*hvs.TrustReport, error) {
	defaultLog.Trace("hosttrust/trust_report:verifyFlavors() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:verifyFlavors() Leaving")

	collectiveTrustReport := hvs.TrustReport{}

	// need to create a map to hold all the untrusted individual reports and group them by the flavor part/type.
	untrusted := struct {
		report        hvs.TrustReport
		flavorPartMap map[hvs.FlavorPartName][]flavorReport
	}{
		report:        hvs.TrustReport{},
		flavorPartMap: make(map[hvs.FlavorPartName][]flavorReport),
	}

	newTrustCaches := make([]uuid.UUID, 0, len(flavors))
	for _, signedFlavor := range flavors {
		for _, flvMatchPolicy := range hostTrustReqs.FlavorMatchPolicies {
			// TODO
			// check nil pointer for Meta, Description
			// if these field are not changed to value type
			flvPart := signedFlavor.Flavor.Meta.Description[hvs.FlavorPartDescription].(string)
			if flvPart == flvMatchPolicy.FlavorPart.String() {

				individualTrustReport, err := v.FlavorVerifier.Verify(hostData, &signedFlavor, v.SkipFlavorSignatureVerification)
				if err != nil {
					return &hvs.TrustReport{}, errors.Wrap(err, "hosttrust/trust_report:verifyFlavors() Error verifying flavor")
				}
				if individualTrustReport.Trusted {
					if reflect.DeepEqual(collectiveTrustReport, hvs.TrustReport{}) {
						collectiveTrustReport = *individualTrustReport
					} else {
						collectiveTrustReport.AddResults(individualTrustReport.Results)
					}
					newTrustCaches = append(newTrustCaches, signedFlavor.Flavor.Meta.ID)
				} else {
					// will need the fault count later on... just iterate through the results and determine the fault count
					faults := 0
					for _, result := range individualTrustReport.Results {
						faults += len(result.Faults)
						for _, fault := range result.Faults {
							log.Debugf("Flavor [%s] did not match host [%s] due to fault: %s",
								signedFlavor.Flavor.Meta.ID, hostID, fault.Name)
						}
					}
					untrusted.flavorPartMap[flvMatchPolicy.FlavorPart] =
						append(untrusted.flavorPartMap[flvMatchPolicy.FlavorPart], flavorReport{
							id:         signedFlavor.Flavor.Meta.ID,
							flavorPart: flvMatchPolicy.FlavorPart,
							report:     individualTrustReport,
							faultCount: faults,
						})

				}
			}
		}
	}

	for flavPart, flavPartReports := range untrusted.flavorPartMap {
		log.Debug("hosttrust/trust_report:verifyFlavors() Processing untrusted trust report for flavor part:", flavPart)
		if hostTrustReqs.DefinedAndRequiredFlavorTypes[flavPart] &&
			len(collectiveTrustReport.Results) == 0 || !collectiveTrustReport.IsTrustedForMarker(flavPart.String()) {
			if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && matchPolicy.MatchType == hvs.MatchTypeAllOf {
				log.Debug("hosttrust/trust_report:verifyFlavors() Flavor Part :", flavPart, " requires ALL_OF policy - each untrusted flavor needs to be added to collective report")
				for _, flavorReport := range flavPartReports {
					log.Debug("Adding untrusted trust report to collective report for ALL_OF flavor part", flavPart, " with flavor ID ", flavorReport.id)
					collectiveTrustReport.AddResults(flavorReport.report.Results)
					newTrustCaches = append(newTrustCaches, flavorReport.id)
				}

			} else if matchPolicy, matchPolicyExists := hostTrustReqs.FlavorPartMatchPolicy[flavPart]; matchPolicyExists && (matchPolicy.MatchType == hvs.MatchTypeAnyOf ||
				matchPolicy.MatchType == hvs.MatchTypeLatest) {
				log.Debug("hosttrust/trust_report:verifyFlavors() Flavor part requires ANY_OF policy, untrusted flavor report with least faults must be added to the collective report", flavPart)
				var leastFaultReport *flavorReport
				for _, flavorReport := range flavPartReports {

					//TODO: implement after GetFaults() is implemented
					if leastFaultReport == nil || flavorReport.faultCount < leastFaultReport.faultCount {
						leastFaultReport = &flavorReport
					}
				}
				if leastFaultReport != nil {
					log.Debug("hosttrust/trust_report:verifyFlavors() Adding untrusted trust report to collective report for ANY_OF flavor part, ",
						leastFaultReport.flavorPart, "with flavor ID ", leastFaultReport.id)
					collectiveTrustReport.AddResults(leastFaultReport.report.Results)
					newTrustCaches = append(newTrustCaches, leastFaultReport.id)
				}
			}
		}
	}
	if len(collectiveTrustReport.Results) == 0 {
		//TODO - check if we return an error here
		return &hvs.TrustReport{
			HostManifest: *hostData,
		}, nil
	}
	// save the trust cache // ignore error since it is just a cache.
	if _, err := v.HostStore.AddTrustCacheFlavors(hostID, newTrustCaches); err != nil {
		log.Error("hosttrust/trust_report:verifyFlavors() error while adding flavor trust cache to store for host id ", hostID, "error - ", err)
	}

	return &collectiveTrustReport, nil
}

// FlavorVerify.java: 684
// TODO find flavors by required key value
func (v *Verifier) findFlavors(flavorGroupID uuid.UUID, latestReqAndDefFlavorTypes map[hvs.FlavorPartName]bool, hostManifestMap map[hvs.FlavorPartName][]models.FlavorMetaKv) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("hosttrust/trust_report:findFlavors() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:findFlavors() Leaving")

	flvrFilterCriteria := models.FlavorVerificationFC{
		FlavorFC: models.FlavorFilterCriteria{
			FlavorgroupID: flavorGroupID,
		},
		FlavorPartsWithLatest: latestReqAndDefFlavorTypes,
		FlavorMeta:            hostManifestMap,
	}

	signedFlavors, err := v.FlavorStore.Search(&flvrFilterCriteria)
	if err != nil {
		return nil, err
	}
	defaultLog.Debugf("%v from Flavorgroup %d Flavors retrieved for verification", flavorGroupID, len(signedFlavors))
	return signedFlavors, nil
}

func getHostManifestMap(hostManifest *hvs.HostManifest, flavorParts []hvs.FlavorPartName) (map[hvs.FlavorPartName][]models.FlavorMetaKv, error) {
	defaultLog.Trace("hosttrust/trust_report:getHostManifestMap() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getHostManifestMap() Leaving")

	hostInfo := hostManifest.HostInfo
	hostInfoValues := make(map[hvs.FlavorPartName][]models.FlavorMetaKv)
	if len(flavorParts) > 0 {
		for _, fp := range flavorParts {
			if fp == hvs.FlavorPartPlatform {
				var pfQueryAttrs []models.FlavorMetaKv
				if hostInfo.BiosName != "" {
					pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
						Key:   "bios.bios_name",
						Value: hostInfo.BiosName,
					})
				}
				if hostInfo.BiosVersion != "" {
					pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
						Key:   "bios.bios_version",
						Value: hostInfo.BiosVersion,
					})
				}
				if utils.IsLinuxHost(&hostInfo) {
					pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.tboot_installed",
						Value: hostInfo.TbootInstalled,
					})
				}
				if !reflect.DeepEqual(hostInfo.HardwareFeatures, taModel.HardwareFeatures{}) {
					if hostInfo.HardwareFeatures.CBNT != nil && hostInfo.HardwareFeatures.CBNT.Enabled &&
						hostInfo.HardwareFeatures.CBNT.Meta.Profile != "BTGP0" {
						pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
							Key:   "hardware.feature.CBNT.meta.profile",
							Value: hostInfo.HardwareFeatures.CBNT.Meta.Profile,
						})
					}
					if hostInfo.HardwareFeatures.UEFI != nil && hostInfo.HardwareFeatures.UEFI.Enabled {
						pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
							Key:   "hardware.feature.UEFI.enabled",
							Value: hostInfo.HardwareFeatures.UEFI.Enabled,
						})
					}
					if hostInfo.HardwareFeatures.UEFI != nil && hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled {
						pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
							Key:   "hardware.feature.UEFI.meta.secure_boot_enabled",
							Value: hostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled,
						})
					}
					if hostInfo.HardwareFeatures.TPM != nil && hostInfo.HardwareFeatures.TPM.Enabled {
						pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
							Key:   "hardware.feature.TPM.enabled",
							Value: hostInfo.HardwareFeatures.TPM.Enabled,
						})
					}
					pfQueryAttrs = append(pfQueryAttrs, models.FlavorMetaKv{
						Key:   "hardware.feature.TXT.enabled",
						Value: hostInfo.HardwareFeatures.TXT.Enabled,
					})
				}
				hostInfoValues[hvs.FlavorPartPlatform] = pfQueryAttrs
			} else if fp == hvs.FlavorPartOs {
				var osfQueryAttrs []models.FlavorMetaKv
				if utils.IsLinuxHost(&hostInfo) {
					osfQueryAttrs = append(osfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.tboot_installed",
						Value: hostInfo.TbootInstalled,
					})
				}
				if hostInfo.OSName != "" {
					osfQueryAttrs = append(osfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.os_name",
						Value: hostInfo.OSName,
					})
				}
				if hostInfo.OSVersion != "" {
					osfQueryAttrs = append(osfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.os_version",
						Value: hostInfo.OSVersion,
					})
				}
				if hostInfo.VMMVersion != "" {
					osfQueryAttrs = append(osfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.vmm_version",
						Value: hostInfo.VMMVersion,
					})
				}
				if hostInfo.VMMName != "" {
					osfQueryAttrs = append(osfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.vmm_name",
						Value: hostInfo.VMMName,
					})
				}
				hostInfoValues[hvs.FlavorPartOs] = osfQueryAttrs
			} else if fp == hvs.FlavorPartHostUnique {
				var hufQueryAttrs []models.FlavorMetaKv
				if utils.IsLinuxHost(&hostInfo) {
					hufQueryAttrs = append(hufQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.tboot_installed",
						Value: hostInfo.TbootInstalled,
					})
				}
				if hostInfo.HardwareUUID != "" {
					hufQueryAttrs = append(hufQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.hardware_uuid",
						Value: strings.ToLower(hostInfo.HardwareUUID),
					})
				}
				hostInfoValues[hvs.FlavorPartHostUnique] = hufQueryAttrs
			} else if fp == hvs.FlavorPartAssetTag {
				var atfQueryAttrs []models.FlavorMetaKv
				if hostInfo.HardwareUUID != "" {
					atfQueryAttrs = append(atfQueryAttrs, models.FlavorMetaKv{
						Key:   "meta.description.hardware_uuid",
						Value: strings.ToLower(hostInfo.HardwareUUID),
					})
				}
				hostInfoValues[hvs.FlavorPartAssetTag] = atfQueryAttrs
			} else if fp == hvs.FlavorPartSoftware {
				var sfQueryAttrs []models.FlavorMetaKv
				if !reflect.DeepEqual(&hostManifest.PcrManifest, hvs.PcrManifest{}) && len(hostManifest.MeasurementXmls) >= 1 {
					measurementLabels, err := getMeasurementLabels(hostManifest)
					if err != nil {
						return hostInfoValues, errors.Wrap(err, "error while getting labels from measurement XML")
					}
					sfQueryAttrs = append(sfQueryAttrs, models.FlavorMetaKv{
						Key:   "SoftwareLabels",
						Value: measurementLabels,
					})
				}
				hostInfoValues[hvs.FlavorPartSoftware] = sfQueryAttrs
			} else if fp == hvs.FlavorPartIma {
				var imaFlavorQueryAttributes []models.FlavorMetaKv
				imaFlavorQueryAttributes = append(imaFlavorQueryAttributes, models.FlavorMetaKv{
					Key:   "meta.description.label",
					Value: "Isecl_IMA",
				})
				hostInfoValues[hvs.FlavorPartIma] = imaFlavorQueryAttributes
			} else {
				return nil, errors.New("Invalid flavor part - " + fp.String())
			}
		}
	}
	return hostInfoValues, nil
}

// get software labels from the host manifest
func getMeasurementLabels(hostManifest *hvs.HostManifest) ([]string, error) {
	defaultLog.Trace("hosttrust/trust_report:getMeasurementLabels() Entering")
	defer defaultLog.Trace("hosttrust/trust_report:getMeasurementLabels() Leaving")

	var measurementLabels []string
	for _, measurementXml := range hostManifest.MeasurementXmls {
		var measurement taModel.Measurement
		err := xml.Unmarshal([]byte(measurementXml), &measurement)
		if err != nil {
			return nil, errors.Wrap(err, "An error occurred parsing measurement xml")
		}
		measurementLabels = append(measurementLabels, measurement.Label)
	}
	return measurementLabels, nil
}
