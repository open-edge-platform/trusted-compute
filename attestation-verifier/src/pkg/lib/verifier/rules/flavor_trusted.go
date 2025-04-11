/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants/verifier-rules-and-faults"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

func NewFlavorTrusted(signedFlavor *hvs.SignedFlavor, flavorSigningCertificate *x509.Certificate, flavorCaCertificates *x509.CertPool, marker hvs.FlavorPartName) (Rule, error) {

	return &flavorTrusted{
		signedFlavor:             signedFlavor,
		flavorId:                 signedFlavor.Flavor.Meta.ID,
		flavorSigningCertificate: flavorSigningCertificate,
		flavorCaCertificates:     flavorCaCertificates,
		marker:                   marker,
	}, nil
}

type flavorTrusted struct {
	signedFlavor             *hvs.SignedFlavor
	flavorId                 uuid.UUID
	flavorSigningCertificate *x509.Certificate
	flavorCaCertificates     *x509.CertPool
	marker                   hvs.FlavorPartName
}

// - If the flavor does not have a signature create a FaultFlavorSignatureMissing
// - If the flavor's signature does not verify with the signing certificate and CAs, create a
//   FaultFlavorSignatureNotTrusted
// - If any errors occur during verification, create FaultFlavorSignatureVerificationFailed
func (rule *flavorTrusted) Apply(hostManifest *hvs.HostManifest) (*hvs.RuleResult, error) {

	result := hvs.RuleResult{}
	result.Trusted = true
	result.Rule.Name = constants.RuleFlavorTrusted
	result.Rule.Markers = append(result.Rule.Markers, rule.marker)

	if len(rule.signedFlavor.Signature) == 0 {
		fault := hvs.Fault{
			Name:        constants.FaultFlavorSignatureMissing,
			Description: fmt.Sprintf("Signature is missing for flavor with id %s", rule.flavorId),
		}

		result.Faults = append(result.Faults, fault)
	} else if rule.flavorSigningCertificate == nil {
		log.Error("FlavorSignatureVerificationFailed fault: The flavor signing certificate was not provided")
		result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
	} else if rule.flavorCaCertificates == nil {
		log.Error("FlavorSignatureVerificationFailed fault: The flavor signing CA certificates were not provided")
		result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
	} else {

		// verify the cert and ca...
		opts := x509.VerifyOptions{
			Roots: rule.flavorCaCertificates,
		}

		_, err := rule.flavorSigningCertificate.Verify(opts)
		if err != nil {
			log.Error("FlavorSignatureVerificationFailed fault: The flavor signing certificate did not validate against the CAs")
			result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
			return &result, nil
		}

		// get the public key for verifying the signed flavor
		var ok bool
		var publicKey *rsa.PublicKey
		if publicKey, ok = rule.flavorSigningCertificate.PublicKey.(*rsa.PublicKey); !ok {
			log.Error("FlavorSignatureVerificationFailed fault: Could not get the flavor signing certificate's public key")
			result.Faults = append(result.Faults, newFlavorSignatureVerificationFailed(rule.flavorId))
			return &result, nil
		}

		err = rule.signedFlavor.Verify(publicKey)
		if err != nil {
			log.WithError(err).Error("FlavorSignatureVerificationFailed fault: Flavor Signature verification failed")
			fault := hvs.Fault{
				Name:        constants.FaultFlavorSignatureNotTrusted,
				Description: fmt.Sprintf("Signature is not trusted for flavor with id %s", rule.flavorId),
			}

			result.Faults = append(result.Faults, fault)
		}
	}

	return &result, nil
}
