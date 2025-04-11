/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/types"
)

type VendorHostConnectorFactory interface {
	GetHostConnector(vendorConnector types.VendorConnector, aasApiUrl string, trustedCaCerts []x509.Certificate, imaMeasureEnabled bool) (HostConnector, error)
}
