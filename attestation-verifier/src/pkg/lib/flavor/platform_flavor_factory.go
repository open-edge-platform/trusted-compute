/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto/x509"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/types"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

/**
 *
 * @author mullas
 */

var log = commLog.GetDefaultLogger()

// FlavorProvider is an interface for PlatformFlavorProvider for a PlatformFlavorProvider
type FlavorProvider interface {
	GetPlatformFlavor() (*types.PlatformFlavor, error)
	GetGenericPlatformFlavor(hcConstants.Vendor) (*types.PlatformFlavor, error)
}

// PlatformFlavorProvider is a factory for the PlatformFlavor which is responsible for instantiating
// an appropriate platform flavor implementation, based on the target host.
type PlatformFlavorProvider struct {
	hostManifest         *hvs.HostManifest
	attributeCertificate *hvs.X509AttributeCertificate
	FlavorTemplates      []hvs.FlavorTemplate
}

// NewPlatformFlavorProvider returns an instance of PlaformFlavorProvider
func NewPlatformFlavorProvider(hostManifest *hvs.HostManifest, tagCertificate *x509.Certificate, flvrTemplates []hvs.FlavorTemplate) (FlavorProvider, error) {
	log.Trace("flavor/platform_flavor_factory:NewPlatformFlavorProvider() Entering")
	defer log.Trace("flavor/platform_flavor_factory:NewPlatformFlavorProvider() Leaving")

	var pfp FlavorProvider
	var tc *hvs.X509AttributeCertificate
	var err error

	// we can skip the check for hostManifest nil, since it will not be required for GenericPlatformFlavor
	// check if attributeCertificate is populated and get the corresponding X509AttributeCertificate
	if tagCertificate != nil {
		tc, err = hvs.NewX509AttributeCertificate(tagCertificate)
		if err != nil {
			return nil, errors.Wrap(err, "Error while generating X509AttributeCertificate from TagCertificate")
		}
	}

	pfp = PlatformFlavorProvider{
		hostManifest:         hostManifest,
		attributeCertificate: tc,
		FlavorTemplates:      flvrTemplates,
	}
	return pfp, nil
}

// GetPlatformFlavor parses the connection string of the target host and determines the type of the host
// and instantiates the appropriate PlatformFlavor implementation.
func (pff PlatformFlavorProvider) GetPlatformFlavor() (*types.PlatformFlavor, error) {
	log.Trace("flavor/platform_flavor_factory:GetPlatformFlavor() Entering")
	defer log.Trace("flavor/platform_flavor_factory:GetPlatformFlavor() Leaving")

	var err error
	var rp types.PlatformFlavor

	if pff.hostManifest != nil {
		rp = types.NewHostPlatformFlavor(pff.hostManifest, pff.attributeCertificate, pff.FlavorTemplates)
	} else {
		err = errors.New("Error while retrieving PlaformFlavor - missing HostManifest")
		return nil, errors.Wrapf(err, common.INVALID_INPUT().Message)
	}

	return &rp, err
}

// GetGenericPlatformFlavor creates an instance of a GenericPlatform flavor using tagCert and vendor
func (pff PlatformFlavorProvider) GetGenericPlatformFlavor(vendor hcConstants.Vendor) (*types.PlatformFlavor, error) {
	log.Trace("flavor/platform_flavor_factory:GetGenericPlatformFlavor() Entering")
	defer log.Trace("flavor/platform_flavor_factory:GetGenericPlatformFlavor() Leaving")

	var err error
	var gpf types.PlatformFlavor

	if pff.attributeCertificate == nil {
		err = errors.New("Tag certificate missing")
		return nil, errors.Wrapf(err, common.INVALID_INPUT().Message)
	}

	log.Info("GetGenericPlatformFlavor: creating generic platform flavor for tag certificate with host hardware UUID {}", pff.attributeCertificate.Subject)

	gpf = types.GenericPlatformFlavor{
		Vendor:         vendor,
		TagCertificate: pff.attributeCertificate,
	}

	return &gpf, nil

}
