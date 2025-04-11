/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"fmt"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type CACertificatesClient interface {
	GetCaCertsInPem(string) ([]byte, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type caCertificatesClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

// GetCaCerts method is used to get all the CA certs of HVS
func (client *caCertificatesClientImpl) GetCaCertsInPem(domain string) ([]byte, error) {
	log.Trace("hvsclient/ca_certificates_client:GetCaCertsInPem() Entering")
	defer log.Trace("hvsclient/ca_certificates_client:GetCaCertsInPem() Leaving")

	url := fmt.Sprintf("%sca-certificates?domain=%s", client.cfg.BaseURL, domain)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/ca_certificates_client:GetCaCertsInPem() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/x-pem-file")
	response, err := client.httpClient.Do(request)

	var cert []byte
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/ca_certificates_client:GetCaCertsInPem() Error sending request")
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("hvsclient/ca_certificates_client:GetCaCertsInPem() Request made to %s returned status %d", url, response.StatusCode)
	}

	cert, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/ca_certificates_client:GetCaCertsInPem() Error reading response")
	}

	return cert, nil
}
