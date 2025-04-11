/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/saml"
	flavorVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

var ErrInvalidHostManiFest = errors.New("invalid host data")
var ErrManifestMissingHwUUID = errors.New("host data missing hardware uuid")

type Verifier struct {
	FlavorStore                     domain.FlavorStore
	FlavorGroupStore                domain.FlavorGroupStore
	HostStore                       domain.HostStore
	ReportStore                     domain.ReportStore
	FlavorVerifier                  flavorVerifier.Verifier
	CertsStore                      crypt.CertificatesStore
	SamlIssuer                      saml.IssuerConfiguration
	SkipFlavorSignatureVerification bool
	hostQuoteReportCache            map[uuid.UUID]*models.QuoteReportCache
	HostTrustCache                  *lru.Cache
}

func NewVerifier(cfg domain.HostTrustVerifierConfig) domain.HostTrustVerifier {
	return &Verifier{
		FlavorStore:                     cfg.FlavorStore,
		FlavorGroupStore:                cfg.FlavorGroupStore,
		HostStore:                       cfg.HostStore,
		ReportStore:                     cfg.ReportStore,
		FlavorVerifier:                  cfg.FlavorVerifier,
		CertsStore:                      cfg.CertsStore,
		SamlIssuer:                      cfg.SamlIssuerConfig,
		SkipFlavorSignatureVerification: cfg.SkipFlavorSignatureVerification,
		HostTrustCache:                  cfg.HostTrustCache,
		hostQuoteReportCache:            make(map[uuid.UUID]*models.QuoteReportCache),
	}
}

func getTrustPcrListReport(hostInfo taModel.HostInfo, report *hvs.TrustReport) []int {
	defaultLog.Trace("hosttrust/verifier:getTrustPcrListReport() Entering")
	defer defaultLog.Trace("hosttrust/verifier:getTrustPcrListReport() Leaving")

	trustPcrMap := make(map[int]struct{})
	var trustPcrList []int

	for _, result := range report.Results {
		if result.Rule.ExpectedPcr != nil {
			pcrIndex := result.Rule.ExpectedPcr.Pcr.Index
			if _, ok := trustPcrMap[pcrIndex]; !ok {
				trustPcrMap[pcrIndex] = struct{}{}
				trustPcrList = append(trustPcrList, pcrIndex)
			}
		}
	}
	if len(trustPcrList) > 0 && utils.IsLinuxHost(&hostInfo) {
		trustPcrList = append(trustPcrList, int(hvs.PCR15))
	}
	return trustPcrList
}

func (v *Verifier) Verify(hostId uuid.UUID, hostData *hvs.HostManifest, newData bool, preferHashMatch bool) (*models.HVSReport, error) {
	defaultLog.Trace("hosttrust/verifier:Verify() Entering")
	defer defaultLog.Trace("hosttrust/verifier:Verify() Leaving")

	defaultLog.Debugf("hosttrust/verifier:Verify() host - %s", hostId.String())

	if hostData == nil {
		return nil, ErrInvalidHostManiFest
	}

	hwUuid, err := uuid.Parse(hostData.HostInfo.HardwareUUID)
	if err != nil || hwUuid == uuid.Nil {
		defaultLog.Errorf("hosttrust/verifier:Verify() host - %s, %s", hostId.String(), ErrManifestMissingHwUUID)
		return nil, ErrManifestMissingHwUUID
	}

	// check if the data has not changed
	if preferHashMatch {
		cacheEntry, ok := v.HostTrustCache.Get(hostId)
		// check if the PCR Values are unchanged.
		if ok {
			cachedQuote := cacheEntry.(*models.QuoteReportCache)
			if cachedQuote.QuoteDigest != "" && hostData.QuoteDigest == cachedQuote.QuoteDigest {
				// retrieve the stored report
				log.Debugf("hosttrust/verifier:Verify() Quote values matches cached value for host %s - skipping flavor verification", hostId.String())
				if report, err := v.refreshTrustReport(hostId, cachedQuote); err == nil {
					return report, err
				} else {
					// log warning message here - continue as normal and create a report from newly fetched data
					log.Warnf("hosttrust/verifier:Verify() - error encountered while refreshing report for host %s - err : %s", hostId.String(), err.Error())
				}
			}
		}
	}
	// TODO : remove this when we remove the intermediate collection
	flvGroupIds, err := v.HostStore.SearchFlavorgroups(hostId)
	flvGroups, err := v.FlavorGroupStore.Search(&models.FlavorGroupFilterCriteria{Ids: flvGroupIds})
	if err != nil {
		return nil, errors.New("hosttrust/verifier:Verify() Store access error")
	}
	// start with the presumption that final trust report would be true. It as some point, we get an invalid report,
	// the Overall trust status would be negative
	var finalReportValid = true // This is the final trust report - initialize
	// create an empty trust report with the host manifest
	finalTrustReport := hvs.TrustReport{HostManifest: *hostData}

	// Get the types of host unique flavors (such as HOST_UNIQUE and ASSET_TAG) that exist for the host.
	// This can be used when determining the flavor groups requirement for each flavors.
	// It will reduce the number of calls made to the database to determine this list. Since it applicable for
	// all flavorgroups, repeated calls can be avoided

	hostUniqueFlavorParts, err := v.HostStore.RetrieveDistinctUniqueFlavorParts(hostId)
	if err != nil {
		return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving host unique flavor parts")
	}
	// convert hostUniqueFlavorParts to a map
	hostUniqueFlavorPartsMap := make(map[hvs.FlavorPartName]bool)

	for _, flavorPart := range hostUniqueFlavorParts {
		hostUniqueFlavorPartsMap[hvs.FlavorPartName(flavorPart)] = true
	}

	for _, fg := range flvGroups {
		//TODO - handle errors in case of DB transaction
		fgTrustReqs, err := NewFlvGrpHostTrustReqs(hostId, hostUniqueFlavorPartsMap, fg, v.FlavorStore, v.FlavorGroupStore, hostData, v.SkipFlavorSignatureVerification)
		if err != nil {
			return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving NewFlvGrpHostTrustReqs")
		}
		fgCachedFlavors, err := v.getCachedFlavors(hostId, (fg).ID)
		if err != nil {
			return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving getCachedFlavors")
		}

		var fgTrustCache hostTrustCache
		if len(fgCachedFlavors) > 0 {
			fgTrustCache, err = v.validateCachedFlavors(hostId, hostData, fgCachedFlavors)
			if err != nil {
				return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while validating cache")
			}
		}

		fgTrustReport := fgTrustCache.trustReport
		if !fgTrustReqs.MeetsFlavorGroupReqs(fgTrustCache, v.FlavorVerifier.GetVerifierCerts()) {
			log.Debug("hosttrust/verifier:Verify() Trust cache doesn't meet flavorgroup requirements")
			finalReportValid = false
			fgTrustReport, err = v.CreateFlavorGroupReport(hostId, *fgTrustReqs, hostData, fgTrustCache)
			if err != nil {
				return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while creating flavorgroup report")
			}
		}
		log.Debug("hosttrust/verifier:Verify() Trust status for host id ", hostId, " for flavorgroup ", fg.ID, " is ", fgTrustReport.IsTrusted())
		// append the results
		finalTrustReport.AddResults(fgTrustReport.Results)
	}
	// create a new report if we actually have any results and either the Final Report is untrusted or
	// we have new Data from the host and therefore need to update based on the new report.
	var hvsReport *models.HVSReport
	log.Debugf("hosttrust/verifier:Verify() Final results in report: %d", len(finalTrustReport.Results))
	if len(finalTrustReport.Results) > 0 && (!finalReportValid || newData) {
		log.Debugf("hosttrust/verifier:Verify() Generating new SAML for host: %s", hostId)
		samlReportGen := NewSamlReportGenerator(&v.SamlIssuer)
		samlReport := samlReportGen.GenerateSamlReport(&finalTrustReport)
		finalTrustReport.Trusted = finalTrustReport.IsTrusted()
		log.Debugf("hosttrust/verifier:Verify() Saving new report for host: %s", hostId)
		// new report - save it to the cache
		trustPcrList := getTrustPcrListReport(hostData.HostInfo, &finalTrustReport)
		defaultLog.Infof("hosttrust/verifier:add() PCR List %v for host %v ", hostId, trustPcrList)
		newCacheEntry := &models.QuoteReportCache{
			QuoteDigest:  hostData.QuoteDigest,
			TrustPcrList: trustPcrList,
			TrustReport:  &finalTrustReport,
		}
		v.HostTrustCache.Add(hostId, newCacheEntry)
		hvsReport = v.storeTrustReport(hostId, &finalTrustReport, &samlReport)
	}
	if hvsReport == nil {
		log.Infof("hosttrust/verifier:Verify() Unable to generate report for the host : %v as no rules found to be applied", hostId)
	}
	return hvsReport, nil
}

func (v *Verifier) getCachedFlavors(hostId uuid.UUID, flavGrpId uuid.UUID) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("hosttrust/verifier:getCachedFlavors() Entering")
	defer defaultLog.Trace("hosttrust/verifier:getCachedFlavors() Leaving")
	// retrieve the IDs of the trusted flavors from the host store
	if flIds, err := v.HostStore.RetrieveTrustCacheFlavors(hostId, flavGrpId); err != nil && len(flIds) == 0 {
		return nil, errors.Wrap(err, "hosttrust/verifier:Verify() Error while retrieving TrustCacheFlavors")
	} else {
		result := make([]hvs.SignedFlavor, 0, len(flIds))
		for _, flvId := range flIds {
			if flv, err := v.FlavorStore.Retrieve(flvId); err == nil {
				result = append(result, *flv)
			}
		}
		return result, nil
	}
}

func (v *Verifier) validateCachedFlavors(hostId uuid.UUID,
	hostData *hvs.HostManifest,
	cachedFlavors []hvs.SignedFlavor) (hostTrustCache, error) {
	defaultLog.Trace("hosttrust/verifier:validateCachedFlavors() Entering")
	defer defaultLog.Trace("hosttrust/verifier:validateCachedFlavors() Leaving")

	htc := hostTrustCache{
		hostID: hostId,
	}
	var collectiveReport hvs.TrustReport
	var trustCachesToDelete []uuid.UUID
	for _, cachedFlavor := range cachedFlavors {
		//TODO: change the signature verification depending on decision on signed flavors
		report, err := v.FlavorVerifier.Verify(hostData, &cachedFlavor, v.SkipFlavorSignatureVerification)
		if err != nil {
			return hostTrustCache{}, errors.Wrap(err, "hosttrust/verifier:validateCachedFlavors() Error from flavor verifier")
		}
		if report.Trusted {
			htc.addTrustedFlavors(&cachedFlavor.Flavor)
			collectiveReport.Results = append(collectiveReport.Results, report.Results...)
		} else {
			trustCachesToDelete = append(trustCachesToDelete, cachedFlavor.Flavor.Meta.ID)
		}
	}
	if len(trustCachesToDelete) > 0 {
		// remove cache entries for flavors that could not be verified
		err := v.HostStore.RemoveTrustCacheFlavors(hostId, trustCachesToDelete)
		if err != nil {
			return hostTrustCache{}, errors.Wrap(err, "could not remove trust cache flavors")
		}
	}
	htc.trustReport = collectiveReport
	return htc, nil
}

func (v *Verifier) refreshTrustReport(hostID uuid.UUID, cache *models.QuoteReportCache) (*models.HVSReport, error) {
	defaultLog.Trace("hosttrust/verifier:refreshTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/verifier:refreshTrustReport() Leaving")
	log.Debugf("hosttrust/verifier:refreshTrustReport() Generating SAML for host: %s using existing trust report", hostID)

	samlReportGen := NewSamlReportGenerator(&v.SamlIssuer)
	samlReport := samlReportGen.GenerateSamlReport(cache.TrustReport)
	return v.storeTrustReport(hostID, cache.TrustReport, &samlReport), nil
}

func (v *Verifier) storeTrustReport(hostID uuid.UUID, trustReport *hvs.TrustReport, samlReport *saml.SamlAssertion) *models.HVSReport {
	defaultLog.Trace("hosttrust/verifier:storeTrustReport() Entering")
	defer defaultLog.Trace("hosttrust/verifier:storeTrustReport() Leaving")

	log.Debugf("hosttrust/verifier:storeTrustReport() flavorverify host: %s SAML Report: %s", hostID, samlReport.Assertion)
	hvsReport := models.HVSReport{
		HostID:      hostID,
		TrustReport: *trustReport,
		CreatedAt:   samlReport.CreatedTime,
		Expiration:  samlReport.ExpiryTime,
		Saml:        samlReport.Assertion,
	}
	report, err := v.ReportStore.Update(&hvsReport)
	if err != nil {
		log.WithError(err).Errorf("hosttrust/verifier:storeTrustReport() Failed to store Report")
	}
	return report
}
