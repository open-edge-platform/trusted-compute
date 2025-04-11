/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"bytes"
	"crypto/tls"
	"errors"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	"net/http"
)

type Client struct {
	BaseURL    string
	JWTToken   []byte
	HTTPClient *http.Client
}

var (
	ErrFailToGetRootCA = errors.New("Failed to retrieve root CA")
	ErrSignCSRFailed   = errors.New("Failed to sign certificate with CMS")
)

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		tlsConfig := tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}
		// Skipping verification as it is done manually using digest of the TLS certificate as this is step of setting up service
		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}
		c.HTTPClient = &http.Client{Transport: &transport}
	}
	return c.HTTPClient
}

func (c *Client) GetRootCA() (string, error) {

	url := clients.ResolvePath(c.BaseURL, "cms/v1/ca-certificates")
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/x-pem-file")
	rsp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusOK {
		return "", ErrFailToGetRootCA
	}
	resBuf := new(bytes.Buffer)
	_, err = resBuf.ReadFrom(rsp.Body)
	if err != nil {
		return "", err
	}
	resStr := resBuf.String()
	return resStr, nil
}

func (c *Client) PostCSR(csr []byte) (string, error) {

	url := clients.ResolvePath(c.BaseURL, "cms/v1/certificates")
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(csr))

	req.Header.Set("Accept", "application/x-pem-file")
	req.Header.Set("Content-Type", "application/x-pem-file")

	req.Header.Add("Authorization", "Bearer "+string(c.JWTToken))
	if c.HTTPClient == nil {
		return "", errors.New("jwtClient.GetJWTSigningCert: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	if rsp.StatusCode != http.StatusOK {
		return "", ErrSignCSRFailed
	}
	resBuf := new(bytes.Buffer)
	_, err = resBuf.ReadFrom(rsp.Body)
	if err != nil {
		return "", err
	}
	resStr := resBuf.String()
	return resStr, nil
}
