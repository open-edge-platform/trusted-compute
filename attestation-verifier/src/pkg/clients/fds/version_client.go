/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package fds

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/util"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
)

func (f *fdsClient) GetVersion() (string, error) {
	log.Trace("clients/fds:GetVersion() Entering")
	defer log.Trace("clients/fds:GetVersion() Leaving")

	versionURL, _ := url.Parse("version")
	reqURL := f.BaseURL.ResolveReference(versionURL)

	req, err := http.NewRequest("GET", reqURL.String(), nil)
	if err != nil {
		return "", errors.Wrap(err, "clients/fds:GetVersion() Error forming request")
	}
	response, err := util.SendNoAuthRequest(req, f.CaCerts)
	if err != nil {
		return "", errors.Wrap(err, "clients/fds:GetVersion() Error reading response body while fetching the version")
	}

	return string(response), nil
}
