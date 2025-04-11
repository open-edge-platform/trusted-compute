/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package vs

import (
	"crypto/x509"
	"net/http"
	"net/url"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/util"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

//Client Details for vsclient
type Client struct {
	BaseURL   *url.URL
	AASURL    *url.URL
	UserName  string
	Password  string
	CertArray []x509.Certificate
}

//TODO move to hvs client and use hvs client factory method for instantiating clients
//GetSamlReports Get HVS Saml host reports
func (c Client) GetSamlReports(url string) ([]byte, error) {
	log.Trace("vs/client:GetSamlReports() Entering")
	defer log.Trace("vs/client:GetSamlReports() Leaving")

	// Create a new request using http
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "vs/clients:GetSamlReports() Error forming request")
	}
	req.Header.Add("Accept", "application/samlassertion+xml")

	response, err := util.SendRequest(req, c.AASURL.String(), c.UserName, c.Password, c.CertArray)
	if err != nil {
		return nil, errors.Wrap(err, "vs/clients:GetSamlReports() Error reading response body while fetching report")
	}
	return response, nil
}

func (c Client) GetCaCerts(domain string) ([]byte, error) {
	log.Trace("vs/client:GetCaCerts() Entering")
	defer log.Trace("vs/client:GetCaCerts() Leaving")

	requestURL, err := url.Parse(c.BaseURL.String() + "ca-certificates?domain=" + domain)
	if err != nil {
		return nil, errors.Wrap(err, "vs/client:GetCaCerts() Error parsing URL")
	}

	req, err := http.NewRequest(http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "vs/client:GetCaCerts() Error forming request")
	}
	req.Header.Set("Accept", "application/x-pem-file")

	cacerts, err := util.SendNoAuthRequest(req, c.CertArray)
	if err != nil {
		return nil, errors.Wrap(err, "vs/client:GetCaCerts() Error while reading response body")
	}

	return cacerts, nil
}
