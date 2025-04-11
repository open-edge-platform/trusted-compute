/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package clients

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
)

type HTTPClientErr struct {
	ErrMessage string
	RetCode    int
	RetMessage string
}

func (ucErr *HTTPClientErr) Error() string {
	return fmt.Sprintf("%s: %d: %s", ucErr.ErrMessage, ucErr.RetCode, ucErr.RetMessage)
}

func HTTPClient() *http.Client {
	return &http.Client{}
}

func HTTPClientTLSNoVerify() *http.Client {
	//InsecureSkipVerify is set to true as connection is established from utility script and k8s plugin
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true},
			Proxy: http.ProxyFromEnvironment,
		},
	}
}

func HTTPClientWithCA(caCertificates []x509.Certificate) (*http.Client, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: false,
		RootCAs:            GetCertPool(caCertificates),
	}
	tr := &http.Transport{TLSClientConfig: config, Proxy: http.ProxyFromEnvironment}
	return &http.Client{Transport: tr}, nil
}

func ResolvePath(baseURL, path string) string {
	if baseURL == "" ||
		path == "" {
		return ""
	}
	if strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL[:len(baseURL)-1]
	}
	if strings.HasPrefix(path, "/") {
		path = path[1:]
	}
	return baseURL + "/" + path
}

func GetCertPool(trustedCACerts []x509.Certificate) *x509.CertPool {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	for i := range trustedCACerts {
		rootCAs.AddCert(&trustedCACerts[i])
	}
	return rootCAs
}
