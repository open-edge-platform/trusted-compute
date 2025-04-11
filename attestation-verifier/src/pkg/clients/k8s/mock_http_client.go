/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package k8s

import (
	"io"
	"net/http"
	"strings"
)

type ClientMock struct{}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewClientMock() HttpClient {
	return &ClientMock{}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {
	stringReader := strings.NewReader("12345")
	stringReadCloser := io.NopCloser(stringReader)

	return &http.Response{StatusCode: 400, Body: stringReadCloser}, nil
}
