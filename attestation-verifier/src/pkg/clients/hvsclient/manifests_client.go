/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type ManifestsClient interface {
	GetManifestXmlById(manifestUUID string) ([]byte, error)
	GetManifestXmlByLabel(manifestLabel string) ([]byte, error)
}

// The Manifest xml (below) is pretty extensive, this endpoint just needs the UUID and Label
// for validating the request body.
//
// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Application_Flavor_v4.6_TPM2.0" Uuid="1fe1b7fc-99e6-4e7e-ba3d-d9aeeb03d227" DigestAlg="SHA384">
// <File Path="/opt/trustagent/.*" SearchType="regex"/>
// </Manifest>
type Manifest struct {
	UUID  string `xml:"Uuid,attr"`
	Label string `xml:"Label,attr"`
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type manifestsClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *manifestsClientImpl) getManifestXml(params map[string]string) ([]byte, error) {
	log.Trace("hvsclient/manifests_client:getManifestXml() Entering")
	defer log.Trace("hvsclient/manifests_client:getManifestXml() Leaving")

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/manifests_client:getManifestXml() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "manifests")

	request, err := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/manifests_client:getManifestXml() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/xml")

	query := request.URL.Query()

	for key := range params {
		query.Add(key, params[key])
	}

	request.URL.RawQuery = query.Encode()

	log.Debugf("hvsclient/manifests_client:getManifestXml() Request URL raw query %s", request.URL.RawQuery)

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/manifests_client:getManifestXml() Error while sending request to %s", parsedUrl)
	}

	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("hvsclient/manifests_client:getManifestXml() Request made to %s returned status %d", parsedUrl, response.StatusCode)
	}

	xml, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("hvsclient/manifests_client:getManifestXml() Error reading response: %s", err)
	}

	log.Debugf("hvsclient/manifests_client:getManifestXml() returned xml response: %s", string(xml))

	return xml, nil
}

func (client *manifestsClientImpl) GetManifestXmlById(manifestUUID string) ([]byte, error) {
	log.Trace("hvsclient/manifests_client:GetManifestXmlById() Entering")
	defer log.Trace("hvsclient/manifests_client:GetManifestXmlById() Leaving")

	params := map[string]string{"id": manifestUUID}
	return client.getManifestXml(params)
}

func (client *manifestsClientImpl) GetManifestXmlByLabel(manifestLabel string) ([]byte, error) {
	log.Trace("hvsclient/manifests_client:GetManifestXmlByLabel() Entering")
	defer log.Trace("hvsclient/manifests_client:GetManifestXmlByLabel() Leaving")

	params := map[string]string{"key": "label", "value": manifestLabel}
	return client.getManifestXml(params)
}
