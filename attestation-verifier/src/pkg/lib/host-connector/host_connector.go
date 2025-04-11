/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/vmware/govmomi/vim25/mo"
)

type HostConnector interface {
	GetHostDetails() (taModel.HostInfo, error)
	GetHostManifest(pcrList []int) (hvs.HostManifest, error)
	DeployAssetTag(string, string) error
	DeploySoftwareManifest(taModel.Manifest) error
	GetMeasurementFromManifest(taModel.Manifest) (taModel.Measurement, error)
	GetTPMQuoteResponse(nonce string, pcrList []int) ([]byte, []byte, *x509.Certificate, *pem.Block, taModel.TpmQuoteResponse, error)
	GetClusterReference(string) ([]mo.HostSystem, error)
}
