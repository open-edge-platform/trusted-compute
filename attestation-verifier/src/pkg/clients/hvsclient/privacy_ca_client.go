/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"bytes"
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

//-------------------------------------------------------------------------------------------------
// Public interface/structures
//-------------------------------------------------------------------------------------------------

type PrivacyCAClient interface {
	DownloadPrivacyCa() ([]byte, error)
	GetIdentityProofRequest(identityChallengeRequest *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error)
	GetIdentityProofResponse(identityChallengeResponse *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error)
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type privacyCAClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client *privacyCAClientImpl) DownloadPrivacyCa() ([]byte, error) {
	log.Trace("hvsclient/privacy_ca_client:DownloadPrivacyCa() Entering")
	defer log.Trace("hvsclient/privacy_ca_client:DownloadPrivacyCa() Leaving")

	var ca []byte

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:DownloadPrivacyCa() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "ca-certificates/aik")

	request, err := http.NewRequest(http.MethodGet, parsedUrl.String(), nil)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:DownloadPrivacyCa() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	response, err := client.httpClient.Do(request)
	var caCert hvs.CaCertificate
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/privacy_ca_client:DownloadPrivacyCa() Error while sending request to %s ", parsedUrl)
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Errorf("hvsclient/privacy_ca_client:DownloadPrivacyCa() Request sent to %s returned status %d", parsedUrl, response.StatusCode)
	}

	ca, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:DownloadPrivacyCa() Error reading response")
	}

	dec := json.NewDecoder(bytes.NewReader(ca))
	dec.DisallowUnknownFields()
	err = dec.Decode(&caCert)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:DownloadPrivacyCa() Error decoding response")
	}

	return caCert.Certificate, nil
}

func (client *privacyCAClientImpl) GetIdentityProofRequest(identityChallengeRequest *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error) {
	log.Trace("hvsclient/privacy_ca_client:GetIdentityProofRequest() Entering")
	defer log.Trace("hvsclient/privacy_ca_client:GetIdentityProofRequest() Leaving")

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:GetIdentityProofRequest() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "privacyca/identity-challenge-request")

	return client.SendIdentityChallengeRequest(parsedUrl, identityChallengeRequest)
}

func (client *privacyCAClientImpl) GetIdentityProofResponse(identityChallengeResponse *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error) {
	log.Trace("hvsclient/privacy_ca_client:GetIdentityProofResponse() Entering")
	defer log.Trace("hvsclient/privacy_ca_client:GetIdentityProofResponse() Leaving")

	parsedUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:GetIdentityProofResponse() error parsing base url")
	}

	parsedUrl.Path = path.Join(parsedUrl.Path, "privacyca/identity-challenge-response")

	return client.SendIdentityChallengeRequest(parsedUrl, identityChallengeResponse)
}

func (client *privacyCAClientImpl) SendIdentityChallengeRequest(url *url.URL, payload *taModel.IdentityChallengePayload) (*taModel.IdentityProofRequest, error) {
	log.Trace("hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Entering")
	defer log.Trace("hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Leaving")

	var identityProofRequest taModel.IdentityProofRequest
	jsonData, err := json.Marshal(*payload)
	if err != nil {
		return nil, err
	}

	log.Debugf("ChallengeRequest: %s", jsonData)

	request, err := http.NewRequest(http.MethodPost, url.String(), bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:SendIdentityChallengeRequest() error creating request")
	}
	request.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.httpClient.Do(request)
	if err != nil {
		secLog.Warn(message.BadConnection)
		return nil, errors.Wrapf(err, "hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Error sending request to %s", url)
	}
	if response.StatusCode != http.StatusOK {
		b, _ := ioutil.ReadAll(response.Body)
		return nil, errors.Errorf("hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Request sent to %s returned status '%d', Response: %s", url, response.StatusCode, string(b))
	}

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Error reading response")
	}

	err = json.Unmarshal(data, &identityProofRequest)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/privacy_ca_client:SendIdentityChallengeRequest() Error while unmarshalling response")
	}

	return &identityProofRequest, nil
}
