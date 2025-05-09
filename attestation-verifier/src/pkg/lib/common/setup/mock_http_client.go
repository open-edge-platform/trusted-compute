/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
)

type ClientMock struct {
	statusType string
}

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewClientMock(statusType string) HttpClient {
	return &ClientMock{statusType: statusType}
}

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {

	if c.statusType == "200" {
		return &http.Response{StatusCode: 200, Body: ioutil.NopCloser(bytes.NewReader([]byte(caCert))), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{getCert()}}}, nil
	} else if c.statusType == "400" {
		return &http.Response{StatusCode: 400, Body: ioutil.NopCloser(bytes.NewReader([]byte(caCert))), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{getCert()}}}, nil
	} else if c.statusType == "Invalid tls" {
		return &http.Response{StatusCode: 500, Body: ioutil.NopCloser(bytes.NewReader([]byte(caCert))), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{&x509.Certificate{}}}}, nil
	} else if c.statusType == "Invalid body content" {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(errReader(0)), TLS: &tls.ConnectionState{PeerCertificates: []*x509.Certificate{getCert()}}}, nil
	}
	return nil, nil
}

var caCert = `-----BEGIN CERTIFICATE-----
MIIELDCCApSgAwIBAgIBADANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
AxMFQ01TQ0EwHhcNMjIwMTA0MDgzNzM3WhcNMjcwMTA0MDgzNzM3WjBHMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
TDEOMAwGA1UEAxMFQ01TQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
gQDM/HzjdhVfoEIl5t61RKvFTTmT5m+LnGaQ/L1rrg8KgDhTfW2fkEoVzt00jk8O
GhQ8zMw7gkY+Vk+4CgzbCDkIV7RUP9tZ0iiM29CO9VCOGcsF81nOSyrDEYJrDUxi
qpG41+QySOc4+KuLjcTjEjtXcxFUtnsxfhCYKUOLwVSh8YQKttFfeZ8Td/ruekQY
6jrFjvXLEVr7rtYcRcq8Gs/dGL54IlvFgDaofzX+KkhuhcBaB2WCny9zlfnsuryV
wjKqS09UKO/X7IUSOG+g5okRenqC/MP5Hp7CIUReBLedcvCCGVAvrTth3ol9EcLi
2ukasbo9Vhb/eJd3axvU3+AGXUthKFF4rphPkwdcRWq1aY1vAROPzm8Pvc9FAxtk
VJ2x2P0awQkbOeiScB+KzjFvIzSdVnxDwfWPneXOQDxc5/u/umb28YEZP+vFBXVz
vSIGzCY9ZwnwKLKULkTgZclY59mD79M3i2DG7gNvHb335JIof0z1RVx8Dgx1GBzt
U+UCAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wDQYJ
KoZIhvcNAQEMBQADggGBAE7ZmNBIU5nKK3VvIfCv79+iq7KUfFc+tYAiM6igjroM
I6sMykqATEeQuu6N/7DR1bIvREMKVGXi6UwcRziXP9tJ71Zew2weBOrUNCYnCdrz
PNKBHSVJsHfcaAx39f6tcQj+bxMHeHB70L5hE2OWD7YlNxA5mCj395uOdELSK6H/
bioToPBRCmAh6hsnPiga0MEiaVVRKQh6qNqzly0hqOe8hkIf29z6xD5UIHyAy8ZW
2CRgLTteEOmikZH6YSRZALTGExe97bKDRgAeoZ/bgR7/wFMPXYi5jUZZRRvIPC0L
1CgoHZsGKUeRonBiUyNC9yzVWzNLukuHdhCv5S8ZgrS6rCDMLHncWH6G2STlqEzU
++LfGXNyx58enoUKo0hYxm33Bw/IjVaqTXg22RwkbvsAAI0AFH/0wrNtWiBNsj4P
C/uYh+7Z+Lc01gd4OwziIGdhuaEQDeq7tcJaXw+H0CvyPWHheSMsfVjIRG2vUgt8
IGqOzVAoSIShq8t9exKF6w==
-----END CERTIFICATE-----
`

func getCert() *x509.Certificate {
	block, _ := pem.Decode([]byte(caCert))
	cert, err := x509.ParseCertificate([]byte(block.Bytes))
	if err != nil {
		log.Println(err)
		return nil
	}
	return cert
}

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}
