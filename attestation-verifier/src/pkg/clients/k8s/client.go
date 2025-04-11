/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/pkg/errors"
)

var log = commLog.GetDefaultLogger()

// K8s Interface for creating new K8sclient and getting response from K8sclient
type K8s interface {
	NewK8sClient(url string, token string, certPath string) (*Client, error)
	SendRequest(reqParams *RequestParams) (*http.Response, error)
}

// Client Details for K8sclient
type Client struct {
	BaseURL    *url.URL
	Token      string
	CertPath   string
	HTTPClient HttpClient
}

// RequestParams request params for K8sclient response
type RequestParams struct {
	Method            string
	URL               *url.URL
	Body              io.Reader
	AdditionalHeaders map[string]string
}

// NewK8sClient create the new K8s client
func NewK8sClient(baseURL *url.URL, token string, certPath string) (*Client, error) {
	log.Trace("K8s/client:NewK8sClient() Entering")
	defer log.Trace("K8s/client:NewK8sClient() Leaving")

	k8sClient := Client{
		BaseURL:  baseURL,
		Token:    token,
		CertPath: certPath,
	}

	err := k8sClient.validateKubernetesDetails()
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:NewK8sClient() Invalid K8s details provided")
	}

	k8sHTTPClient, err := k8sClient.getK8sHTTPClient()
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:NewK8sClient() Error in creating new HTTP/HTTPS client for K8s")
	}
	k8sClient.HTTPClient = k8sHTTPClient

	return &k8sClient, nil
}

// validateKubernetesDetails validations for API details
func (k8sClient *Client) validateKubernetesDetails() error {
	log.Trace("K8s/client:validateKubernetesDetails() Entering")
	defer log.Trace("K8s/client:validateKubernetesDetails() Leaving")

	protocols := make(map[string]byte)
	protocols["http"] = 0
	protocols["https"] = 0

	err := validation.ValidateURL(k8sClient.BaseURL.String(), protocols, "/")
	if err != nil {
		return errors.Wrap(err, "K8s/client:validateKubernetesDetails() K8s URL is Not Valid")
	}

	err = validation.ValidateJWT(k8sClient.Token)
	if err != nil {
		return errors.Wrap(err, "K8s/client:validateKubernetesDetails() K8s token is Not Valid")
	}

	if k8sClient.CertPath != "" {
		if _, err := os.Stat(k8sClient.CertPath); err != nil {
			return errors.Wrap(err, "K8s/client:validateKubernetesDetails() K8s cert file cannot be read")
		}
	}

	return nil
}

// SendRequest send request to get response from K8s apiserver
func (k8sClient *Client) SendRequest(reqParams *RequestParams) (*http.Response, error) {
	log.Trace("K8s/client:SendRequest() Entering")
	defer log.Trace("K8s/client:SendRequest() Leaving")

	if k8sClient == nil || k8sClient.HTTPClient == nil {
		return nil, errors.New("K8s/client:SendRequest() K8s client not initialized properly")
	}

	err := k8sClient.validateKubernetesDetails()
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:SendRequest() K8s Details are not valid")
	}

	request, err := http.NewRequest(reqParams.Method, reqParams.URL.String(), reqParams.Body)
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:SendRequest() Error in creating Request")
	}

	request.Header.Add("Authorization", "Bearer "+k8sClient.Token)
	if len(reqParams.AdditionalHeaders) > 0 {
		for key, value := range reqParams.AdditionalHeaders {
			request.Header.Add(key, value)
		}
	}

	res, err := k8sClient.HTTPClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:SendRequest() Error in receiving response")
	}

	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated || res.StatusCode == http.StatusNoContent || res.StatusCode == http.StatusNotFound {
		return res, nil
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "K8s/client:SendRequest() Error while reading response body")
	}
	return res, errors.Errorf("K8s/client:SendRequest(): Error in receiving response from k8s %s", string(body))

}

// getK8sHTTPClient get the K8s client
func (k8sClient *Client) getK8sHTTPClient() (HttpClient, error) {
	log.Trace("K8s/client:getK8sHTTPClient() Entering")
	defer log.Trace("K8s/client:getK8sHTTPClient() Leaving")

	if k8sClient.HTTPClient != nil {
		return k8sClient.HTTPClient, nil
	}

	var k8sHTTPClient *http.Client

	if k8sClient.CertPath != "" {
		var certArray []x509.Certificate

		x509Certificate, err := crypt.GetCertFromPemFile(k8sClient.CertPath)
		if err != nil {
			return nil, errors.Wrap(err, "K8s/client:getK8sHTTPClient() Unable to Read X509 Certificate")
		}
		certArray = append(certArray, *x509Certificate)

		newTLSClient, err := clients.HTTPClientWithCA(certArray)
		if err != nil {
			return nil, errors.Wrap(err, "K8s/client:getK8sHTTPClient() Error in creating client with certPath "+k8sClient.CertPath)
		}
		k8sHTTPClient = newTLSClient
	} else {
		//we need a TLS no verify while running setup tasks because certs not exchanged at this point of time.
		log.Debug("K8s/client:getK8sHTTPClient() Creating Insecure K8s Client")
		k8sHTTPClient = clients.HTTPClientTLSNoVerify()
	}
	k8sHTTPClient.Transport.(*http.Transport).TLSClientConfig.MinVersion = tls.VersionTLS13
	return k8sHTTPClient, nil

}
