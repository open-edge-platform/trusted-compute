/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"crypto/x509"
	"fmt"
	"time"

	faultsConst "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

func NewTagCertificateTrusted(assetTagCACertificates *x509.CertPool, attributeCertificate *hvs.X509AttributeCertificate) (Rule, error) {
	if assetTagCACertificates == nil {
		return nil, errors.New("The tag certificates cannot be nil")
	}

	rule := TagCertificateTrusted{
		assetTagCACertificates: assetTagCACertificates,
		attributeCertificate:   attributeCertificate,
	}

	return &rule, nil
}

type TagCertificateTrusted struct {
	assetTagCACertificates *x509.CertPool
	attributeCertificate   *hvs.X509AttributeCertificate
}

// - If the X509AttributeCertificate is null, raise TagCertificateMissing fault.
// - Otherwise, verify the the attributeCert agains the list of CAs.
// - If the attributeCertificate is valid but has a 'NotBefore' value before 'today,
//   raise a TagCertificateNotYetValid fault.
// - If the attributeCertificate is valid but has a 'NotAfter' value after 'today,
//   raise a TagCertificateNotYetExpired fault.
func (rule *TagCertificateTrusted) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {

	var fault *hvs.Fault
	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = faultsConst.RuleTagCertificateTrusted
	result.Rule.Markers = append(result.Rule.Markers, hvs.FlavorPartAssetTag)

	if rule.attributeCertificate == nil {
		fault = &hvs.Fault{
			Name:        faultsConst.FaultTagCertificateMissing,
			Description: "Host trust policy requires tag validation but the tag certificate was not found",
		}
	} else {

		tagCertificate, err := x509.ParseCertificate(rule.attributeCertificate.Encoded)
		if err != nil {
			return nil, errors.Wrap(err, "Could not parse attribute certificate")
		}

		opts := x509.VerifyOptions{
			Roots: rule.assetTagCACertificates,
		}

		_, err = tagCertificate.Verify(opts)
		if err != nil {
			fault = &hvs.Fault{
				Name:        faultsConst.FaultTagCertificateNotTrusted,
				Description: "Tag certificate is not signed by any trusted CA",
			}
		} else {
			// check to see if the attribute certificate's 'not before' is before today...
			if time.Now().Before(rule.attributeCertificate.NotBefore) {
				fault = &hvs.Fault{
					Name:        faultsConst.FaultTagCertificateNotYetValid,
					Description: fmt.Sprintf("Tag certificate not valid before %s", rule.attributeCertificate.NotBefore),
				}
			}

			// check to see if the attributes certificate's 'not after' is after today...
			if time.Now().After(rule.attributeCertificate.NotAfter) {
				fault = &hvs.Fault{
					Name:        faultsConst.FaultTagCertificateExpired,
					Description: fmt.Sprintf("Tag certificate not valid after %s", rule.attributeCertificate.NotAfter),
				}
			}

		}
	}

	if fault != nil {
		result.Faults = append(result.Faults, *fault)
	}

	return &result, nil
}
