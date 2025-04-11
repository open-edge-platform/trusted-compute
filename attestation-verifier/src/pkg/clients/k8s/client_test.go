/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package k8s

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/mux"
)

var k8sURL = "https://localhost:8771/"

var k8scertFilePath = "../../ihub/test/resources/k8scert.pem"

func mockServer(t *testing.T) *httptest.Server {
	r := mux.NewRouter()

	r.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("12345"))
	}).Methods(http.MethodGet)

	return httptest.NewServer(r)

}

func TestNewK8sClient(t *testing.T) {

	certificatePath := k8scertFilePath

	type args struct {
		baseURL  string
		token    string
		certPath string
	}
	tests := []struct {
		name    string
		args    args
		want    *Client
		wantErr bool
	}{
		{
			name: "Test 1 - success scenario",
			args: args{
				baseURL:  k8sURL,
				token:    k8sToken,
				certPath: certificatePath,
			},
			wantErr: false,
		},
		{
			name: "Test 2 - failure scenario",
			args: args{
				baseURL:  k8sURL,
				token:    k8sToken,
				certPath: "test",
			},
			wantErr: true,
		},
		{
			name: "Test 3 - failure scenario",
			args: args{
				baseURL:  "",
				token:    "",
				certPath: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urlPath := tt.args.baseURL

			parsedUrl, err := url.Parse(urlPath)
			if err != nil {
				t.Errorf("k8s/client_test:TestNewK8sClient(): Unable to parse the url,error = %v", err)
				return
			}

			_, err = NewK8sClient(parsedUrl, tt.args.token, tt.args.certPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("k8s/client_test:TestNewK8sClient(): error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestSendRequest(t *testing.T) {
	server := mockServer(t)
	var err error
	defer server.Close()

	urlPath := server.URL + "/test"
	parsedUrl, err := url.Parse(urlPath)
	if err != nil {
		t.Errorf("k8s/client_test:TestSendRequest(): Unable to parse the url,error = %v", err)
		return
	}

	parsedK8sUrl, err := url.Parse(k8sURL)
	if err != nil {
		t.Errorf("k8s/client_test:TestSendRequest(): Unable to parse the k8s url,error = %v", err)
		return
	}
	requestParams1 := RequestParams{
		Method: http.MethodGet,
		URL:    parsedUrl,
	}
	type args struct {
		reqParams *RequestParams
	}
	tests := []struct {
		name    string
		k       *Client
		args    args
		want    *http.Response
		wantErr bool
	}{
		{
			name: "Send Request Test 1 - Success scenario ",
			k: &Client{
				BaseURL:    parsedK8sUrl,
				Token:      k8sToken,
				CertPath:   k8scertFilePath,
				HTTPClient: &http.Client{},
			},
			args: args{
				reqParams: &RequestParams{
					Method: http.MethodGet,
					URL:    parsedUrl,
				},
			},
			wantErr: false,
		},
		{
			name: "Send Request Test 2 - failure scenario",
			k:    nil,
			args: args{
				reqParams: &requestParams1,
			},
			wantErr: true,
		},
		{
			name: "Send Request Test 3 - failure scenario",
			k: &Client{
				BaseURL:    parsedK8sUrl,
				Token:      k8sToken,
				CertPath:   k8scertFilePath,
				HTTPClient: &ClientMock{},
			},
			args: args{
				reqParams: &RequestParams{
					Method: http.MethodGet,
					URL:    parsedUrl,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "Send Request Test 3 - failure scenario" {
				mock := NewClientMock()
				tt.k.HTTPClient = mock
			}
			_, err := tt.k.SendRequest(tt.args.reqParams)
			if (err != nil) != tt.wantErr {
				t.Errorf("k8s/client_test:TestSendRequest(): error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestGetK8sHTTPClient(t *testing.T) {

	certificatePath := k8scertFilePath

	parsedK8sUrl, err := url.Parse(k8sURL)
	if err != nil {
		t.Errorf("k8s/client_test:TestGetK8sHTTPClient(): Unable to parse the k8s url,error = %v", err)
		return
	}

	k1 := Client{
		BaseURL:  parsedK8sUrl,
		Token:    k8sToken,
		CertPath: "",
	}
	k2 := Client{
		BaseURL:  parsedK8sUrl,
		Token:    k8sToken,
		CertPath: certificatePath,
	}
	tests := []struct {
		name       string
		k          *Client
		wantClient bool
		wantErr    bool
	}{
		{
			name:       "Test_getK8sHTTPClient Success Scenario - 1",
			k:          &k1,
			wantClient: true,
			wantErr:    false,
		},
		{
			name:       "Test_getK8sHTTPClient Success Scenario - 2",
			k:          &k2,
			wantClient: true,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := tt.k.getK8sHTTPClient()

			if (err != nil) != tt.wantErr {
				t.Errorf("k8s/client_test:TestGetK8sHTTPClient(): error = %v, wantErr %v", c, tt.wantErr)
				return
			}

			if (c != nil) != tt.wantClient {
				t.Errorf("k8s/client_test:TestGetK8sHTTPClient(): client = %v, wantClient %v", c, tt.wantClient)
				return
			}
		})
	}
}

var k8sToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"
