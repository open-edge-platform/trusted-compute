/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package verifier

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier/rules"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

const (
	authorityKeyIdOid = "2.5.29.35"
)

//getPcrMatchesConstantRules method will create PcrMatchesConstantRule and return the rule
//return nil if error occurs
func getPcrMatchesConstantRules(pcrLogData *hvs.FlavorPcrs, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule
	var rule rules.Rule
	var err error

	rule, err = rules.NewPcrMatchesConstant(pcrLogData, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrMatchesConstant rule ")
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getPcrEventLogEqualsRules method will create PcrEventLogEqualsRule and return the rule
//return nil if error occurs
func getPcrEventLogEqualsRules(pcrLogData *hvs.FlavorPcrs, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	expectedPcrEventLogEntry := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: pcrLogData.Pcr.Index,
			Bank:  pcrLogData.Pcr.Bank,
		},
		TpmEvent: pcrLogData.EventlogEqual.Events,
	}

	rule, err := rules.NewPcrEventLogEquals(&expectedPcrEventLogEntry, uuid.Nil, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEquals rule for bank '%s', index '%d'", pcrLogData.Pcr.Bank, pcrLogData.Pcr.Index)
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getPcrEventLogEqualsExcludingRules method will create PcrEventLogEqualsRule and return the rule
//return nil if error occurs
func getPcrEventLogEqualsExcludingRules(pcrLogData *hvs.FlavorPcrs, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	expectedPcrEventLogEntry := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: pcrLogData.Pcr.Index,
			Bank:  pcrLogData.Pcr.Bank,
		},
		TpmEvent: pcrLogData.EventlogEqual.Events,
	}
	rule, err := rules.NewPcrEventLogEqualsExcluding(&expectedPcrEventLogEntry, pcrLogData.EventlogEqual.ExcludeTags, uuid.Nil, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogEqualsExcluding rule for bank '%s', index '%d'", pcrLogData.Pcr.Bank, pcrLogData.Pcr.Index)
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getPcrEventLogIntegrityRules method will create PcrEventLogIntegrityRule and return the rule
//return nil if error occurs
func getPcrEventLogIntegrityRules(pcrLogData *hvs.FlavorPcrs, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	rule, err := rules.NewPcrEventLogIntegrity(pcrLogData, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIntegrity rule for bank '%s', index '%d'", pcrLogData.Pcr.Bank, pcrLogData.Pcr.Index)
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getAssetTagMatchesRule method will create AssetTagMatchesRule and return the rule
//return nil if error occurs
func getAssetTagMatchesRule(flavor *hvs.Flavor) (rules.Rule, error) {
	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the AssetTagMatches rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	// Load "tags" from the asset tag certificate
	assetTagCertficate, err := x509.ParseCertificate(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, errors.Wrap(err, "Could not parse asset tag certificate")
	}

	tags := make([]hvs.TagKvAttribute, 0)
	for _, extensions := range assetTagCertficate.Extensions {
		/* Per go1.15 release notes https://golang.org/doc/go1.15:
		CreateCertificate now automatically generates the SubjectKeyId if the template is a CA
		and doesn't explicitly specify one: defaults to SHA1 hash of Public component of parent CA.
		AuthKeyId defaults to SubjectKeyId. And this is always added to Certificate.Extensions.
		ASN1 unmarshalling for extension with oid 2.5.29.35 for AuthorityKeyId always seems to fail.
		We skip the verification of this ASN1 to avoid conflicts.*/
		if extensions.Id.String() == authorityKeyIdOid {
			log.Warnf("lib/verifier/getAssetTagMatchesRule: Skipping ASN1 unmarshal for AuthorityKeyId")
			continue
		}
		var tagAttribute hvs.TagKvAttribute
		_, err = asn1.Unmarshal(extensions.Value, &tagAttribute)
		if err != nil {
			return nil, errors.Wrap(err, "Error parsing asset tag attribute")
		}
		tags = append(tags, tagAttribute)
	}

	hash := sha512.New384()
	_, err = hash.Write(flavor.External.AssetTag.TagCertificate.Encoded)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed to write encoded tag certificate")
	}

	expectedAssetTagDigest := hash.Sum(nil)
	// now create the asset tag matches rule...
	rule, err = rules.NewAssetTagMatches(expectedAssetTagDigest, tags)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create the new AssetTagMatches rule")
	}

	return rule, nil
}

//getTagCertificateTrustedRule method will create TagCertificateTrustedRule and return the rule
//return nil if error occurs
func getTagCertificateTrustedRule(assetTagCACertificates *x509.CertPool, flavor *hvs.Flavor) (rules.Rule, error) {
	var rule rules.Rule
	var err error

	// if the flavor has a valid asset tag certificate, add the TagCertificateTrusted rule...
	if flavor.External == nil {
		return nil, errors.New("'External' was not present in the flavor")
	}

	rule, err = rules.NewTagCertificateTrusted(assetTagCACertificates, &flavor.External.AssetTag.TagCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create the TagCertificateTrusted rule")
	}

	return rule, nil
}

//getPcrEventLogIncludesRules method will create PcrEventLogIncludesRule and return the rule
//return nil if error occurs
func getPcrEventLogIncludesRules(pcrLogData *hvs.FlavorPcrs, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	expectedPcrEventLogEntry := hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: pcrLogData.Pcr.Index,
			Bank:  pcrLogData.Pcr.Bank,
		},
		TpmEvent: pcrLogData.EventlogIncludes,
	}

	rule, err := rules.NewPcrEventLogIncludes(&expectedPcrEventLogEntry, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a PcrEventLogIncludes rule for bank '%s', index '%d'", pcrLogData.Pcr.Bank, pcrLogData.Pcr.Index)
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getImaLogIntegrityRules method will create PcrEventLogIntegrityRule and return the rule
//return nil if error occurs
func getImaLogIntegrityRules(pcrLogData *hvs.FlavorPcrs, imaLogData *hvs.Ima, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var pcrRules []rules.Rule

	rule, err := rules.NewImaEventLogIntegrity(pcrLogData, imaLogData, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a ImaLogIntegrity rule")
	}
	pcrRules = append(pcrRules, rule)

	return pcrRules, nil
}

//getPcrEventLogIntegrityRules method will create PcrEventLogIntegrityRule and return the rule
//return nil if error occurs
func getImaEventLogEqualsRules(pcrLogData *hvs.FlavorPcrs, imaLogData *hvs.Ima, marker hvs.FlavorPartName) ([]rules.Rule, error) {
	var imaMatchesRules []rules.Rule

	rule, err := rules.NewImaEventLogEquals(pcrLogData, imaLogData, marker)
	if err != nil {
		return nil, errors.Wrapf(err, "An error occurred creating a ImaEventLogEquals rule for bank")
	}
	imaMatchesRules = append(imaMatchesRules, rule)

	return imaMatchesRules, nil
}
