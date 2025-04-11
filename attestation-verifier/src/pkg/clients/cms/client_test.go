/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package cms

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func mockServer(t *testing.T) *httptest.Server {
	r := mux.NewRouter()

	r.HandleFunc("/cms/v1/ca-certificates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`-----BEGIN CERTIFICATE-----
        MIIENTCCAp2gAwIBAgIBAzANBgkqhkiG9w0BAQwFADBHMQswCQYDVQQGEwJVUzEL
        MAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRFTDEOMAwGA1UE
        AxMFQ01TQ0EwHhcNMjAwMTA5MTUzMzUyWhcNMjUwMTA5MTUzMzUyWjBQMQswCQYD
        VQQGEwJVUzELMAkGA1UECBMCU0YxCzAJBgNVBAcTAlNDMQ4wDAYDVQQKEwVJTlRF
        TDEXMBUGA1UEAxMOQ01TIFNpZ25pbmcgQ0EwggGiMA0GCSqGSIb3DQEBAQUAA4IB
        jwAwggGKAoIBgQCea4dx+Lw3qtg5PZ/ChD6cZzXbzhJPCPBlUG/dU90yYFZR5j3c
        rkC5ZYCb8Bb/iRh1YVLYB1xgLpAB8NQDHSZMSPeIiCBdJttbkDNEA3fGdHRSLEGv
        W0cNinmkzdIg1y2I5i8RrJoKVharS1iR9el4ghVSawW9Z7U25IotmT7auYXDjCny
        Zm5qm8uLlKXJknmIqfT0W1B06jpiBDZV0foBR47Z/1UexpF78l99rAEsF5d5K25c
        5V1O5VfmtHz+H/NpcN+TUBGKZ9NpvX44uEHFH+E7yDENs2y4m6+65ZtAs0pj8pOd
        bMZXdWafaz0XOBnrhgkUMdIakouU9P1RV5I0pR1zfBcYkFNcJYbyR+7G0ZpOedRQ
        4djehZg8LsZU4hGL3k1Q7/QyA0xEclfmIw6zwc9ss3qlYrEPldUPMxzuRxqrQZr0
        g69gRJes3H43mA4GYkb47gbSmGwplDGcTfhrVDuVsiYdKcb8jVf9ggdtJ529dkEs
        EmFl0C7q0NBv/20CAwEAAaMjMCEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQF
        MAMBAf8wDQYJKoZIhvcNAQEMBQADggGBAHBGoc7xPnZ7spHl1SUueZIQkAFrBSGK
        ZaGDufNOxOXiOmxgqJnchL3YKPMmkYwRIPdHPJhCdaTcmhb+phbCHPhj8NycuiPS
        qaK6VCwnT7PN0uaIPNK3qeynme6dnPJwcwMV3AybF9JdoWV+QMZzgwdjEOfDPdxS
        zykODHwgsPGurvyFiIVx2ga90YDSYpin7TPKM5m2RVC2HDfWAZE8+ujf76FgmZ2i
        i8JHRi3rwSWc9mq7yR7H9RWWU1UuhR9zPlgj6f9DCASBpJI1OnrwyS3DQ/ABzuLS
        9jY+vP7DbyRnfJFcUSru0v8pSkoaPICwo1xpQc0hIRrIr0g9VKA+8OUKHgMnXq8L
        tu1zbsbwj8LlJBJrj/y/vwB1dQEQMdAEhUEgLjmEJtc/kMj53EdbTicutiOItBSY
        jwwgh754cwHsSK+pl6Pq3IEqxpZmBgTGTAM195kB5cs1if2oFzwfL2Ik5q4sDAHp
        3NqNon34qP7XcDrUErM+fovIfecnDDsd/g==
        -----END CERTIFICATE-----`))
	}).Methods(http.MethodGet)

	r.HandleFunc("/cms/v1/certificates", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`-----BEGIN CERTIFICATE------
        MIICYzCCAUsCAQAwHjEcMBoGA1UEAwwTV0xTIFRMUyBDZXJ0aWZpY2F0ZTCCASIw
        DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbH0rV5KhRN/xxhAHM1n9r8185w
        Gu21zta4koOXNHGDvM6ePRbfpu8erM54b6BGILLjHfM4iLi5s6iRu6uaNhGkSzAt
        G/J7+K+fR6a1LQ4e7bJbpv7xKz7K7/1ZyIym6c4pxi9i9dib2+CK4H8iNOoYtxCw
        NT19mpo+yWkwrGRr8SRXwZvBJQKKo6wcOHHTdo6OC5aGbBuP0KU7kEK2zIeGFs0h
        7gYi2CUWoPjcckTdZKtyIqEC1RsvIsO44OAhc215JNs+ZJmPAZ6oY3WB47Y997Yf
        Iw3FNTD8pxZRVAd3ngL6R5D3neI/oirryEroemoGF7mQ7uvI/uFVyzUh5dECAwEA
        AaAAMA0GCSqGSIb3DQEBDAUAA4IBAQCjTLp4TuNVCerqrtNYJywj6G1sbCYKzUL1
        EwlliEOUCpXpTIqPcaDTpci6Wsh2rUTdMPzPxY9gqJ8b+ZJYTMsyzslZpdvZCXRt
        0QllF2DS+ETV2DJm7VeikqEjSWrNeQyyFimKo1Eboxr1yZgOClTM2Kq937sE4b/b
        H9xuI8JIu+H8PlCVoecg3n7Xef5yAGK6eTA1pMSMPafB6DngEXlZLsSdB1QcytCJ
        Vo9phrmt6CnVciJqul6ukFzoiRizb2OMU1mpstV/TIuEuR/fSqroZXII4U1xPp82
        1va55WHMBZlmi2T0XC8QKuYMw7FnnWU+whPaBUOgvtFRwoeLKBBR
        -----END CERTIFICATE-------`))
	}).Methods(http.MethodPost)

	return httptest.NewServer(r)

}

func TestCMS(t *testing.T) {

	cms := Client{
		BaseURL: "",
	}
	jwtToken, err := ioutil.ReadFile("/var/jwtToken")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	cms.JWTToken = jwtToken

}

func TestClient_httpClient(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/cms/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient *http.Client
	}
	tests := []struct {
		name   string
		fields fields
		want   *http.Client
	}{
		{
			name: "Validate httpClient",
			fields: fields{
				BaseURL: urlPath,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				BaseURL:    tt.fields.BaseURL,
				JWTToken:   tt.fields.JWTToken,
				HTTPClient: tt.fields.HTTPClient,
			}
			c.httpClient()
		})
	}
}

func TestClient_GetRootCA(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient *http.Client
	}
	tests := []struct {
		name    string
		fields  fields
		want    string
		wantErr bool
	}{
		{
			name: "Validate GetRootCA with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate GetRootCA with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				BaseURL:    tt.fields.BaseURL,
				JWTToken:   tt.fields.JWTToken,
				HTTPClient: tt.fields.HTTPClient,
			}
			_, err := c.GetRootCA()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetRootCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_PostCSR(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient *http.Client
	}
	type args struct {
		csr []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Validate PostCSR with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate PostCSR with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
		{
			name: "Validate PostCSR with NIL Client",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: nil,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				BaseURL:    tt.fields.BaseURL,
				JWTToken:   tt.fields.JWTToken,
				HTTPClient: tt.fields.HTTPClient,
			}
			_, err := c.PostCSR(tt.args.csr)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.PostCSR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
