/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvsclient

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strings"
)

type HVSClientFactory interface {
	HostsClient() (HostsClient, error)
	FlavorsClient() (FlavorsClient, error)
	ManifestsClient() (ManifestsClient, error)
	PrivacyCAClient() (PrivacyCAClient, error)
	ReportsClient() (ReportsClient, error)
	CertifyHostKeysClient() (CertifyHostKeysClient, error)
	CACertificatesClient() (CACertificatesClient, error)
}

type hvsClientConfig struct {
	// BaseURL specifies the URL base for the HVS, for example https://hvs.server:8443/v2
	BaseURL string

	AasAPIUrl string
	// BearerToken is the JWT token required for authentication with external services
	BearerToken string
	// CaCertsDir is required for HTTP Client
	CaCertsDir string

	UserName string

	Password string
}

func NewVSClientFactory(baseURL, bearerToken, caCertsDir string) (HVSClientFactory, error) {

	if bearerToken == "" || baseURL == "" || caCertsDir == "" {
		return nil, errors.New("One or more parameters among bearer token, baseURL and caCertsDir path is empty")
	}
	cfg := hvsClientConfig{BaseURL: baseURL, BearerToken: bearerToken, CaCertsDir: caCertsDir}

	defaultFactory := defaultVSClientFactory{&cfg}
	return &defaultFactory, nil
}

func NewVSClientFactoryWithUserCredentials(baseURL, aasApiUrl, username, password, caCertsDir string) (HVSClientFactory, error) {
	if aasApiUrl == "" || baseURL == "" || caCertsDir == "" || username == "" || password == "" {
		return nil, errors.New("One or more parameters among aasApiUrl, baseURL, username, password and caCertsDir path is empty")
	}

	if !strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL + "/"
	}
	cfg := hvsClientConfig{BaseURL: baseURL, AasAPIUrl: aasApiUrl, UserName: username, Password: password, CaCertsDir: caCertsDir}

	defaultFactory := defaultVSClientFactory{&cfg}
	return &defaultFactory, nil
}

//-------------------------------------------------------------------------------------------------
// Implementation
//-------------------------------------------------------------------------------------------------

type defaultVSClientFactory struct {
	cfg *hvsClientConfig
}

func (vsClientFactory *defaultVSClientFactory) FlavorsClient() (FlavorsClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &flavorsClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) HostsClient() (HostsClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &hostsClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) ManifestsClient() (ManifestsClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &manifestsClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) PrivacyCAClient() (PrivacyCAClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &privacyCAClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) ReportsClient() (ReportsClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &reportsClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) CertifyHostKeysClient() (CertifyHostKeysClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &certifyHostKeysClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) CACertificatesClient() (CACertificatesClient, error) {
	httpClient, err := vsClientFactory.createHttpClient()
	if err != nil {
		return nil, err
	}

	return &caCertificatesClientImpl{httpClient, vsClientFactory.cfg}, nil
}

func (vsClientFactory *defaultVSClientFactory) createHttpClient() (*http.Client, error) {
	log.Trace("hvsclient/hvsclient_factory:createHttpClient() Entering")
	defer log.Trace("hvsclient/hvsclient_factory:createHttpClient() Leaving")

	_, err := url.ParseRequestURI(vsClientFactory.cfg.BaseURL)
	if err != nil {
		return nil, err
	}

	caCerts, err := crypt.GetCertsFromDir(vsClientFactory.cfg.CaCertsDir)
	if err != nil {
		log.WithError(err).Errorf("hvsclient/hvsclient_factory:createHttpClient() Error while getting certs from %s", vsClientFactory.cfg.CaCertsDir)
		return nil, err
	}
	// Here we need to return a client which has validated the HVS TLS cert-chain
	client, err := clients.HTTPClientWithCA(caCerts)
	if err != nil {
		log.WithError(err).Error("hvsclient/hvsclient_factory:createHttpClient() Error while creating http client")
		return nil, err
	}

	return &http.Client{Transport: client.Transport}, nil
}
