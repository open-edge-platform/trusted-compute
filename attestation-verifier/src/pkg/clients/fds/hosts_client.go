/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package fds

import (
	"crypto/x509"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/pkg/errors"
	"net/http"
	"net/url"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/util"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/fds"
)

var log = commLog.GetDefaultLogger()

type Client interface {
	SearchHosts(*fds.HostFilterCriteria) ([]*fds.Host, error)
	GetVersion() (string, error)
}

func NewClient(fdsURL *url.URL, aasBaseURL *url.URL, certs []x509.Certificate, username, password string) Client {
	return &fdsClient{
		BaseURL:    fdsURL,
		AasBaseURL: aasBaseURL,
		CaCerts:    certs,
		Username:   username,
		Password:   password,
	}
}

type fdsClient struct {
	BaseURL    *url.URL
	AasBaseURL *url.URL
	CaCerts    []x509.Certificate
	Username   string
	Password   string
}

func (f *fdsClient) SearchHosts(hostFilterCriteria *fds.HostFilterCriteria) ([]*fds.Host, error) {
	log.Trace("clients/fds:SearchHosts() Entering")
	defer log.Trace("clients/fds:SearchHosts() Leaving")

	hostsURL, _ := url.Parse("hosts")
	reqURL := f.BaseURL.ResolveReference(hostsURL)
	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to create new request")
	}
	req.Header.Set("Accept", constants.HTTPMediaTypeJson)
	query := req.URL.Query()

	if hostFilterCriteria.HostName != "" {
		query.Add("hostName", hostFilterCriteria.HostName)
	}

	if hostFilterCriteria.NameContains != "" {
		query.Add("nameContains", hostFilterCriteria.NameContains)
	}

	if hostFilterCriteria.HardwareId != uuid.Nil {
		query.Add("hostHardwareId", hostFilterCriteria.HardwareId.String())
	}

	req.URL.RawQuery = query.Encode()

	log.Debugf("SearchHosts: %s", req.URL.RawQuery)

	hostDetails, err := util.SendRequest(req, f.AasBaseURL.String(), f.Username, f.Password, f.CaCerts)
	if err != nil {
		log.Error("clients/fds:SearchHosts() Error while sending request")
		return nil, err
	}

	var teeData []*fds.Host
	err = json.Unmarshal(hostDetails, &teeData)
	if err != nil {
		return nil, errors.Wrap(err, "clients/fds:SearchHosts() TEE Platform data unmarshal failed")
	}

	return teeData, nil
}
