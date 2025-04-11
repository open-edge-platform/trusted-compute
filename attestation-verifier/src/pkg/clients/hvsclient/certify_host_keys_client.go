/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"bytes"
	"encoding/json"
	wlaModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

type CertifyHostKeysClient interface {
	CertifyHostSigningKey(*wlaModel.RegisterKeyInfo) ([]byte, error)
	CertifyHostBindingKey(*wlaModel.RegisterKeyInfo) ([]byte, error)
}

type certifyHostKeysClientImpl struct {
	httpClient *http.Client
	cfg        *hvsClientConfig
}

func (client certifyHostKeysClientImpl) CertifyHostSigningKey(key *wlaModel.RegisterKeyInfo) ([]byte, error) {
	log.Trace("hvsclient/certify_host_keys_client:CertifyHostSigningKey Entering")
	defer log.Trace("hvsclient/certify_host_keys_client:CertifyHostSigningKey Leaving")

	certifyKeyUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client.go:CertifyHostSigningKey() error parsing base url")
	}

	certifyKeyUrl.Path = path.Join(certifyKeyUrl.Path, "/rpc/certify-host-signing-key")

	return client.SendCertifyHostKeyRequest(key, certifyKeyUrl)
}

func (client certifyHostKeysClientImpl) CertifyHostBindingKey(key *wlaModel.RegisterKeyInfo) ([]byte, error) {
	log.Trace("hvsclient/certify_host_keys_client:CertifyHostBindingKey Entering")
	defer log.Trace("hvsclient/certify_host_keys_client:CertifyHostBindingKey Leaving")

	certifyKeyUrl, err := url.Parse(client.cfg.BaseURL)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client:CertifyHostBindingKey() error parsing base url")
	}

	certifyKeyUrl.Path = path.Join(certifyKeyUrl.Path, "rpc/certify-host-binding-key")

	return client.SendCertifyHostKeyRequest(key, certifyKeyUrl)
}

func (client certifyHostKeysClientImpl) SendCertifyHostKeyRequest(key *wlaModel.RegisterKeyInfo, certifyKeyUrl *url.URL) ([]byte, error) {
	log.Trace("hvsclient/certify_host_keys_client:SendCertifyHostKeyRequest Entering")
	defer log.Trace("hvsclient/certify_host_keys_client:SendCertifyHostKeyRequest Leaving")

	kiJSON, err := json.Marshal(key)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client.go:SendCertifyHostKeyRequest() error marshalling signing/binding key info")
	}

	req, err := http.NewRequest(http.MethodPost, certifyKeyUrl.String(), bytes.NewBuffer(kiJSON))
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client.go:SendCertifyHostKeyRequest() Failed to create request for certifying signing/binding Key")
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.cfg.BearerToken)
	rsp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client.go:SendCertifyHostKeyRequest() Error from response")
	}
	defer func() {
		derr := rsp.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()
	if rsp.StatusCode != http.StatusCreated {
		return nil, errors.Errorf("hvsclient/certify_host_keys_client.go:SendCertifyHostKeyRequest() request made to %s returned status %d", certifyKeyUrl.String(), rsp.StatusCode)
	}
	body, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "hvsclient/certify_host_keys_client.go:SendCertifyHostKeyRequest() Error from response")
	}

	return body, nil
}
