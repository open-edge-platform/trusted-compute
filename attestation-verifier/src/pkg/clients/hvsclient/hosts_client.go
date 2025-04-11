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

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type HostsClient interface {

	//  Searches for the hosts with the specified criteria.
	SearchHosts(*hvs.HostFilterCriteria) (*hvs.HostCollection, error)

	// Registers the specified host with the Verfication Service.
	CreateHost(*hvs.HostCreateRequest) (*hvs.Host, error)

	//  Updates the host with the specified attributes. Except for the host name, all other attributes can be updated.
	UpdateHost(host *hvs.Host) (*hvs.Host, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type hostsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *hostsClientImpl) SearchHosts(hostFilterCriteria *hvs.HostFilterCriteria) (*hvs.HostCollection, error) {
	log.Trace("hvsclient/hosts_client:SearchHosts() Entering")
	defer log.Trace("hvsclient/hosts_client:SearchHosts() Leaving")

	hosts := hvs.HostCollection{}

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:SearchHosts() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "hosts")

	request, err := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:SearchHosts() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/json")

	query := request.URL.Query()

	if hostFilterCriteria.Id != uuid.Nil {
		query.Add("id", hostFilterCriteria.Id.String())
	}

	if hostFilterCriteria.NameEqualTo != "" {
		query.Add("nameEqualTo", hostFilterCriteria.NameEqualTo)
	}

	if hostFilterCriteria.NameContains != "" {
		query.Add("nameContains", hostFilterCriteria.NameContains)
	}

	if hostFilterCriteria.HostHardwareId != uuid.Nil {
		query.Add("hostHardwareId", hostFilterCriteria.HostHardwareId.String())
	}

	if hostFilterCriteria.Key != "" && hostFilterCriteria.Value != "" {
		query.Add("key", hostFilterCriteria.Key)
		query.Add("value", hostFilterCriteria.Value)
	}

	request.URL.RawQuery = query.Encode()

	log.Debugf("SearchHosts: %s", request.URL.RawQuery)

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/hosts_client:SearchHosts() Error making request to %s", parsedUrl)
	}

	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("hvsclient/hosts_client:SearchHosts() Request made to %s returned status %d", parsedUrl, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrapf(err, "hvsclient/hosts_client:SearchHosts() Error reading response")
	}

	log.Debugf("hvsclient/hosts_client:SearchHosts() SearchHosts returned json: %s", string(data))

	err = json.Unmarshal(data, &hosts)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:SearchHosts() Error while unmarshaling the response")
	}

	return &hosts, nil
}

func (client *hostsClientImpl) CreateHost(hostCreateRequest *hvs.HostCreateRequest) (*hvs.Host, error) {
	log.Trace("hvsclient/hosts_client:CreateHost() Entering")
	defer log.Trace("hvsclient/hosts_client:CreateHost() Leaving")

	var host hvs.Host

	jsonData, err := json.Marshal(hostCreateRequest)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:CreateHost() Error while marshalling hostcreate criteria")
	}
	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:CreateHost() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "hosts")

	request, err := http.NewRequest(http.MethodPost, parsedUrl.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:CreateHost() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	log.Debugf("hvsclient/hosts_client:CreateHost() Sending Post request to url %s with json body: %s ", parsedUrl, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/hosts_client:CreateHost() Error while making request to %s ", parsedUrl)
	}

	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	if response.StatusCode != http.StatusCreated {
		return nil, errors.Errorf("hvsclient/hosts_client:CreateHost() Request made to %s returned status %d", parsedUrl, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:CreateHost() Error reading response ")
	}

	log.Debugf("hvsclient/hosts_client:CreateHost() CreateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &host)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:CreateHost() Error while unmarshalling the response body")
	}

	return &host, nil
}

func (client *hostsClientImpl) UpdateHost(host *hvs.Host) (*hvs.Host, error) {
	log.Trace("hvsclient/hosts_client:UpdateHost() Entering")
	defer log.Trace("hvsclient/hosts_client:UpdateHost() Leaving")

	var updatedHost hvs.Host

	jsonData, err := json.Marshal(host)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:UpdateHost() Error while marshalling request body")
	}

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "clients/hvs_client:certifyHostKey() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "hosts", host.Id.String())

	request, err := http.NewRequest(http.MethodPut, parsedUrl.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:UpdateHost() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	log.Debugf("hvsclient/hosts_client:UpdateHost() Sending PUT request to url %s, json: %s ", parsedUrl, string(jsonData))

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/hosts_client:UpdateHost() Error while sending request to %s", parsedUrl)
	}

	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("hvsclient/hosts_client:UpdateHost() Request made to %s returned status %d", parsedUrl, response.StatusCode)
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:UpdateHost() Error reading response ")
	}

	log.Debugf("hvsclient/hosts_client:UpdateHost() UpdateHost returned json: %s", string(data))

	err = json.Unmarshal(data, &updatedHost)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/hosts_client:UpdateHost() Error while unmarshalling response body")
	}

	return &updatedHost, nil
}
