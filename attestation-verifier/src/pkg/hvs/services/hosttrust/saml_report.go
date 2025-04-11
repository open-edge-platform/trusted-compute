/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hosttrust

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	faultsConst "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	log "github.com/sirupsen/logrus"
)

type SamlReportGenerator struct {
	tagIssuer *saml.IssuerConfiguration
}

func NewSamlReportGenerator(tagIssuer *saml.IssuerConfiguration) *SamlReportGenerator {
	return &SamlReportGenerator{tagIssuer}
}

func (srg *SamlReportGenerator) GenerateSamlReport(report *hvs.TrustReport) saml.SamlAssertion {
	defaultLog.Trace("hosttrust/saml_report:generateSamlReport() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:generateSamlReport() Leaving")

	libSaml, err := saml.NewLegacySAML(*srg.tagIssuer)
	if err != nil {
		log.WithError(err).Errorf("hosttrust/saml_report:generateSamlReport() Failed to instantiate SAML library")
	}
	mapFormatter := saml.NewLegacyMapFormatter(getSamlReportMap(report))
	assertion, err := libSaml.GenerateSamlAssertion(mapFormatter)
	if err != nil {
		log.WithError(err).Errorf("hosttrust/saml_report:generateSamlReport() Failed to generate SAML assertions")
	}
	return assertion
}

// load attributes map for saml report
func getSamlReportMap(t *hvs.TrustReport) map[string]string {
	defaultLog.Trace("hosttrust/saml_report:getSamlReportMap() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:getSamlReportMap() Leaving")

	samlReportMap := make(map[string]string)

	for field, value := range getHostInfoMap(t.HostManifest.HostInfo) {
		samlReportMap[field] = value
	}
	for field, value := range getHardwareFeaturesMap(t.HostManifest.HostInfo.HardwareFeatures) {
		samlReportMap[field] = value
	}
	for field, value := range getMarkersMap(t) {
		samlReportMap[field] = value
	}
	if t.HostManifest.BindingKeyCertificate != "" {
		samlReportMap["Binding_Key_Certificate"] = t.HostManifest.BindingKeyCertificate
	}
	if t.HostManifest.AIKCertificate != "" {
		samlReportMap["AIK_Certificate"] = t.HostManifest.AIKCertificate
	}

	if t.HostManifest.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion != "" {
		samlReportMap["TPMVersion"] = t.HostManifest.HostInfo.HardwareFeatures.TPM.Meta.TPMVersion
	}
	for field, value := range getTags(t) {
		samlReportMap[field] = value
	}

	return samlReportMap
}

// load markers map for saml report
func getMarkersMap(t *hvs.TrustReport) map[string]string {
	defaultLog.Trace("hosttrust/saml_report:getMarkersMap() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:getMarkersMap() Leaving")

	trustedPrefix := "TRUST_"
	markersMap := make(map[string]string)
	for _, flavorType := range hvs.GetFlavorTypes() {
		marker := flavorType.String()
		if len(t.GetResultsForMarker(marker)) > 0 {
			markersMap[trustedPrefix+strings.ToUpper(marker)] = strconv.FormatBool(t.IsTrustedForMarker(marker))
		} else {
			markersMap[trustedPrefix+strings.ToUpper(marker)] = "NA"
		}
	}
	markersMap[trustedPrefix+"OVERALL"] = strconv.FormatBool(t.IsTrusted())
	return markersMap
}

// load host info map for saml report
func getHostInfoMap(hostInfo model.HostInfo) map[string]string {
	defaultLog.Trace("hosttrust/saml_report:getHostInfoMap() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:getHostInfoMap() Leaving")

	hostValues := reflect.ValueOf(hostInfo)
	hostTypes := hostValues.Type()

	hostInfoMap := make(map[string]string)
	for i := 0; i < hostValues.NumField(); i++ {
		if hostTypes.Field(i).Name != "HardwareFeatures" {
			hostInfoMap[hostTypes.Field(i).Name] = fmt.Sprintf("%v", hostValues.Field(i).Interface())
		}
		defaultLog.Debugf("hosttrust/saml_report:getHostInfoMap() Field: %s\tValue: %v\n", hostTypes.Field(i).Name, hostValues.Field(i).Interface())
	}
	return hostInfoMap
}

// load hardware features map for saml report
func getHardwareFeaturesMap(features model.HardwareFeatures) map[string]string {
	defaultLog.Trace("hosttrust/saml_report:getHardwareFeaturesMap() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:getHardwareFeaturesMap() Leaving")

	hwFeaturesMap := make(map[string]string)
	featurePrefix := "FEATURE_"
	if features.CBNT != nil && features.CBNT.Enabled && features.CBNT.Meta.Profile != "" {
		hwFeaturesMap[featurePrefix+constants.Cbnt] = strconv.FormatBool(features.CBNT.Enabled)
		hwFeaturesMap["FEATURE_cbntProfile"] = features.CBNT.Meta.Profile
	}
	if features.UEFI != nil {
		hwFeaturesMap[featurePrefix+constants.Uefi] = strconv.FormatBool(features.UEFI.Enabled)
	}
	if features.UEFI != nil {
		hwFeaturesMap[featurePrefix+constants.SecureBootEnabled] = strconv.FormatBool(features.UEFI.Meta.SecureBootEnabled)
	}
	if features.TPM != nil {
		hwFeaturesMap[featurePrefix+constants.Tpm] = strconv.FormatBool(features.TPM.Enabled)
	}
	if features.TXT != nil {
		hwFeaturesMap[featurePrefix+constants.Txt] = strconv.FormatBool(features.TXT.Enabled)
	}
	return hwFeaturesMap
}

// load tags map for saml report
func getTags(trustReport *hvs.TrustReport) map[string]string {
	defaultLog.Trace("hosttrust/saml_report:getTags() Entering")
	defer defaultLog.Trace("hosttrust/saml_report:getTags() Leaving")

	tagPrefix := "TAG_"
	tagsMap := make(map[string]string)
	for _, result := range trustReport.GetResultsForMarker(hvs.FlavorPartAssetTag.String()) {
		if result.Rule.Name == faultsConst.RuleAssetTagMatches && len(result.Rule.Tags) > 0 {
			for key, value := range result.Rule.Tags {
				tagsMap[tagPrefix+key] = value
			}
		}
	}
	return tagsMap
}
