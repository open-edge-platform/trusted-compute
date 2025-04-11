/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hvsclient

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type FlavorsClient interface {
	CreateFlavor(flavorCreateRequest *hvs.FlavorCreateRequest) (hvs.FlavorCollection, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type flavorsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *flavorsClientImpl) CreateFlavor(flavorCreateRequest *hvs.FlavorCreateRequest) (hvs.FlavorCollection, error) {
	log.Trace("hvsclient/flavors_client:CreateFlavor() Entering")
	defer log.Trace("hvsclient/flavors_client:CreateFlavor() Leaving")

	var flavors hvs.FlavorCollection
	jsonData, err := json.Marshal(flavorCreateRequest)
	if err != nil {
		return flavors, err
	}
	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return flavors, errors.Wrap(err, "hvsclient/flavors_client:CreateFlavor() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "flavors")
	request, err := http.NewRequest(http.MethodPost, parsedUrl.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return flavors, errors.Wrap(err, "hvsclient/flavors_client:CreateFlavor() error creating request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)

	log.Debugf("hvsclient/flavors_client:CreateFlavor() Posting to url %s, json: %s ", parsedUrl, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return flavors, errors.Wrapf(err, "hvsclient/flavors_client:CreateFlavor() Error while making request to %s", parsedUrl)
	}

	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()
	if response.StatusCode != http.StatusCreated {
		return flavors, errors.Errorf("hvsclient/flavors_client:CreateFlavor() request made to %s returned status %d", parsedUrl, response.StatusCode)
	}

	jsonData, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return flavors, errors.Errorf("hvsclient/flavors_client:CreateFlavor() Error reading response")
	}

	log.Debugf("hvsclient/flavors_client:CreateFlavor() Json response body returned: %s", string(jsonData))

	err = json.Unmarshal(jsonData, &flavors)
	if err != nil {
		return flavors, errors.Wrap(err, "hvsclient/flavors_client:CreateFlavor() Error unmarshalling json data to flavors")
	}
	return flavors, nil
}
