/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package util

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"
	"github.com/pkg/errors"
)

func GetEndorsementKeyCertificateBytes(ownerSecretKey string, tpmFactory tpmprovider.TpmFactory) ([]byte, error) {
	log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Entering")
	defer log.Trace("util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Leaving")

	//---------------------------------------------------------------------------------------------
	// Get the endorsement key certificate from the tpm
	//---------------------------------------------------------------------------------------------
	tpm, err := tpmFactory.NewTpmProvider()
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while creating NewTpmProvider")
	}

	defer tpm.Close()

	// check to see if the EK Certificate exists...
	ekCertificateExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "Error checking if the EK Certificate is present")
	}

	if !ekCertificateExists {
		return nil, errors.Errorf("The TPM does not have an RSA EK Certificate at the default index 0x%x", tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	}

	ekCertBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error while performing tpm Nv read operation for getting endorsement certificate in bytes")
	}

	// check if the multi-level EK issuer cert chain is provisioned
	// check to see if the EK Certificate exists...
	eccOnDieCaCertChainExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_X509_P384_EK_CERTCHAIN)
	if err != nil {
		return nil, errors.Wrap(err, "Error checking if the EK Issuing Cert Chain is present")
	}

	// cert chain exists - proceed to retrieve
	if eccOnDieCaCertChainExists {
		issuingCertChainBytes, err := tpm.NvRead(ownerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_X509_P384_EK_CERTCHAIN)
		if err != nil {
			return nil, errors.Wrap(err, "util/endorsement_certificate:GetEndorsementKeyCertificateBytes() Error "+
				"while performing tpm Nv read operation for getting endorsement certificate chain in bytes")
		}

		// assemble the full EC chain with the issuing certificates first
		var fullChainBytes []byte
		fullChainBytes = append(fullChainBytes, issuingCertChainBytes...)
		fullChainBytes = append(fullChainBytes, ekCertBytes...)
		ekCertBytes = fullChainBytes
	}
	return ekCertBytes, nil
}
