/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package host_connector

import (
	"crypto/x509"

	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

// HostConnectorProvider is an interface implemented by HostConnectorFactory for injecting HostConnector instances at runtime
type HostConnectorProvider interface {
	NewHostConnector(string) (HostConnector, error)
}

type HostConnectorFactory struct {
	aasApiUrl         string
	trustedCaCerts    []x509.Certificate
	natsServers       []string
	imaMeasureEnabled bool
}

func NewHostConnectorFactory(aasApiUrl string, trustedCaCerts []x509.Certificate, natsServers []string, imaMeasureEnabled bool) *HostConnectorFactory {
	return &HostConnectorFactory{aasApiUrl, trustedCaCerts, natsServers, imaMeasureEnabled}
}

func (htcFactory *HostConnectorFactory) NewHostConnector(connectionString string) (HostConnector, error) {

	log.Trace("host_connector/host_connector_factory:NewHostConnector() Entering")
	defer log.Trace("host_connector/host_connector_factory:NewHostConnector() Leaving")
	var connectorFactory VendorHostConnectorFactory
	vendorConnector, err := util.GetConnectorDetails(connectionString)
	if err != nil {
		return nil, errors.Wrap(err, "host_connector/host_connector_factory:NewHostConnector() Error getting connector details")
	}

	switch vendorConnector.Vendor {
	case constants.VendorIntel, constants.VendorMicrosoft:
		log.Debug("host_connector/host_connector_factory:NewHostConnector() Connector type for provided connection string is INTEL")
		connectorFactory = &IntelConnectorFactory{htcFactory.natsServers}
	case constants.VendorVMware:
		log.Debug("host_connector/host_connector_factory:NewHostConnector() Connector type for provided connection string is VMWARE")
		connectorFactory = &VmwareConnectorFactory{}
	default:
		return nil, errors.New("host_connector_factory:NewHostConnector() Vendor not supported yet: " + vendorConnector.Vendor.String())
	}
	return connectorFactory.GetHostConnector(vendorConnector, htcFactory.aasApiUrl, htcFactory.trustedCaCerts, htcFactory.imaMeasureEnabled)
}
