/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"net/http"
)

type ClientMock struct{}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewClientMock() HttpClient {
	return &ClientMock{}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {

	return &http.Response{StatusCode: 201, Body: req.Body}, nil
}
