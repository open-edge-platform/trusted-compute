/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/x509"
	"encoding/base64"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type HostManifest struct {
	AIKCertificate        string           `json:"aik_certificate,omitempty"`
	AssetTagDigest        string           `json:"asset_tag_digest,omitempty"`
	HostInfo              taModel.HostInfo `json:"host_info"`
	PcrManifest           PcrManifest      `json:"pcr_manifest"`
	ImaLogs               *ImaLogs         `json:"ima_logs,omitempty"`
	BindingKeyCertificate string           `json:"binding_key_certificate,omitempty"`
	MeasurementXmls       []string         `json:"measurement_xmls,omitempty"`
	QuoteDigest           string           `json:"quote_digest,omitempty"`
}

func (hostManifest *HostManifest) GetAIKCertificate() (*x509.Certificate, error) {

	if len(hostManifest.AIKCertificate) == 0 {
		return nil, errors.New("The AIK is not present in the HostManifest")
	}

	aikBytes, err := base64.StdEncoding.DecodeString(hostManifest.AIKCertificate)
	if err != nil {
		return nil, errors.Wrap(err, "Error decoding the HostManifest's base64 value of the AIK")
	}

	aik, err := x509.ParseCertificate(aikBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Error parse x509 from the HostManifest's certificate bytes")
	}

	return aik, nil
}
