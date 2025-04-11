/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
)

type MockAasClientFactory struct {
	purpose string
}

func NewMockAASClientFactory(purpose string) aas.AasClientProvider {
	return &MockAasClientFactory{
		purpose: purpose,
	}
}

func (aasCp MockAasClientFactory) GetAasClient() (aas.Client, error) {
	client := NewClientMock(aasCp.purpose)
	return aas.Client{
		HTTPClient: client,
	}, nil
}

type ClientMock struct {
	purpose string
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewClientMock(purpose string) HttpClient {
	return &ClientMock{
		purpose: purpose,
	}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {

	if c.purpose == "downloadApiToken" {
		return &http.Response{StatusCode: 200, Body: req.Body}, nil
	}

	return &http.Response{StatusCode: 201, Body: req.Body}, nil
}
