/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	aasTypes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

var BaseURL = "https://localhost:8771/"

var token = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

func mockServer(t *testing.T) *httptest.Server {
	r := mux.NewRouter()

	r.HandleFunc("/aas/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`[{
			"username" : "superadmin",
			"password" : "password",
		}]`))
	}).Methods(http.MethodPost)

	r.HandleFunc("/aas/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`[{
			"user_id" : "1fdb39de-7bf4-440e-ad05-286eca933f78",
			"username" : "superadmin"
		}]`))
	}).Methods(http.MethodGet)

	r.HandleFunc("/aas/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`{
			"name": "CertApprover",
			"service": "CMS"
		 }`))
	}).Methods(http.MethodPost)

	r.HandleFunc("/aas/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`[{
			"role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
			"service": "CMS",
			"name": "CertApprover"
		 }]`))
	}).Methods(http.MethodGet)

	r.HandleFunc("/aas/v1/roles/{role_id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte("204"))
	}).Methods(http.MethodDelete)

	r.HandleFunc("/aas/v1/users/{user_id}/permissions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`[
			{
			   "service": "VS",
			   "rules": [
						  "flavors:search:*",
						  "hosts:create:*"
						]
			}
		 ]`))
	}).Methods(http.MethodGet)

	r.HandleFunc("/aas/v1/users/{user_id}/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`[
			{
			   "role_id": "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
			   "service": "CMS",
			   "name": "CertApprover"
			}
		 ]`))
	}).Methods(http.MethodGet)

	r.HandleFunc("/aas/v1/users/{user_id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`{
			"user_id": "1fdb39de-7bf4-440e-ad05-286eca933f78",
			"username": "vsServiceUser"
		 }`))
	}).Methods(http.MethodPatch)

	r.HandleFunc("/aas/v1/credentials", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`-----BEGIN NATS USER JWT-----
        eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ.eyJleHAiOjE2MjIxMDk1NzEsImp0aSI6IlhIVEhDTFdDTE5YV01ER0tLTE5aSU9GQUdGQUlDTVhRNUgyN0ZUSUhHSVBPNVBUQUE2REEiLCJpYXQiOjE2MjE5MzY3NzEsImlzcyI6IkFBQTZPTU1HR0FNSFAzTlZVU0dBQkkyVVRBN1hIS0JHTEpOTk9KWERaQkk2NU5HVUpXNEFHSEZLIiwic3ViIjoiVUNUTVE1TUhBUE5KU1NQSlJFWk1ZV1dON09NRFpESEZPNlI0N1BXTUc2WlJRQlNSNUpKRk5UVjYiLCJuYXRzIjp7InB1YiI6eyJhbGxvdyI6WyJ0cnVzdC1hZ2VudC5cdTAwM2UiXX0sInN1YiI6eyJhbGxvdyI6WyJfSU5CT1guXHUwMDNlIl19LCJzdWJzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ0eXBlIjoidXNlciIsInZlcnNpb24iOjJ9fQ.eHyGimM4sItxDcfqhEVzhCON8e0qasOT_QX1sxdM0mG9Is_TjK144Pz8U_Ut1jQ7czAi1gzAQZT-fBbyxhw_CA
        ------END NATS USER JWT------
        ************************* IMPORTANT *************************
        NKEY Seed printed below can be used to sign and prove identity.
        NKEYs are sensitive and should be treated as secrets.
        -----BEGIN USER NKEY SEED-----
        SUAE6WDHNRTCY55TBJUMZLRVLWGZXFE7J2O6IKMQDBX4MQDQE5QVBU4NXU
        ------END USER NKEY SEED------
        *************************************************************`))
	}).Methods(http.MethodPost)

	r.HandleFunc("/aas/v1/custom-claims-token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`{
            "subject": "00000000-8887-0f15-0106-1024a5a5a5a5",
            "validity_seconds": 86400,
            "claims": {
                "roles": [{
                    "service": "SCS",
                    "name": "HostDataUpdater"
                },
                {
                    "service": "SCS",
                    "name": "HostDataReader"
                },
                {
                    "service": "SHVS",
                    "name": "HostDataUpdater"
                }]
            }
        }`))
	}).Methods(http.MethodPost)

	r.HandleFunc("/aas/v1/jwt-certificates", func(w http.ResponseWriter, r *http.Request) {
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
	}).Methods(http.MethodPost)

	r.HandleFunc("/aas/v1/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(`eyJhbGciOiJSUzM4NCIsImtpZCI6ImYwY2UyNzhhMGM0OGI5NjE3YzQxNzViYmMz
        ZWIyNThjNDEwYzI2NzUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZ
        SI6IkFBUyIsIm5hbWUiOiJSb2xlTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsI
        m5hbWUiOiJVc2VyTWFuYWdlciJ9LHsic2VydmljZSI6IkFBUyIsIm5hbWUiOiJVc
        2VyUm9sZU1hbmFnZXIifV0sImV4cCI6MTU3OTE4ODEwMSwiaWF0IjoxNTc5MTgwO
        TAxLCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6ImFkbWluX2FhcyJ9.dI95
        8fYhz2RxcnXbeTgmOVTykW6en315lAOofh4kljIAiYJlCzg7EJsr5TysDynlXN1J
        CFHxLXOv2mLwx-VCXUPRvynTuENFUxNxnj13a1SlesYWQMt8cJUUfIHuz8pFWA71
        OIqdR6LO7z98A1HCaM6UDusskw53EpUOx2ZYm_WTxWdnI0Gp-VKMDCt7JlR497o8
        o5xBpiuoeJDd_7fl5lfaOdkocedisAtwqhDxAsMhmlxfJ7CeR5yic1YmVN9kDwjA
        l_IF248K12Vu7QiFsuTt5NJUqyOCWHS1igv_U67-55o5sR37xciDgPg-z1bGIdTm
        g-GxCZQNbo5I6zr5E-_GgzsBfbIWvN_sxFXq7pN3CN7wvCfnEGXsW4coThT2PS6V
        roDctDvds396GUcr1Ra077t8q_ETPStLcuKyAvH994uzyVIIXKZnyb9mjDdYU168
        4G0f6M2HpZoo9DZxeQlGf4RmZVqODSW2FH78f0x0a3UTsLsV02Si0KU1GaI2`))
	}).Methods(http.MethodPost)

	return httptest.NewServer(r)

}

func TestClient_prepReqHeader(t *testing.T) {

	request, _ := http.NewRequest(http.MethodPost, BaseURL, bytes.NewReader([]byte(token)))

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient *http.Client
	}
	type args struct {
		req *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Validate prepReqHeader with valid inputs",
			fields: fields{
				BaseURL:    "https://localhost:8771/",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				req: request,
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
			c.PrepReqHeader(tt.args.req)
		})
	}
}

func TestClient_CreateUser(t *testing.T) {

	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		u types.UserCreate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *types.UserCreateResponse
		wantErr bool
	}{
		{
			name: "Validate CreateUser with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			args: args{
				u: types.UserCreate{
					Name:     "superadmin",
					Password: "P@ssw0rd",
				},
			},
			wantErr: false,
		},
		{
			name: "Validate CreateUser with Invalid Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				u: types.UserCreate{
					Name:     "superadmin",
					Password: "P@ssw0rd",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate CreateUser with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				u: types.UserCreate{
					Name:     "superadmin",
					Password: "P@ssw0rd",
				},
			},
			wantErr: true,
		},
		{
			name: "Validate CreateUser with NIL client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				u: types.UserCreate{
					Name:     "superadmin",
					Password: "P@ssw0rd",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			c := &Client{
				BaseURL:  tt.fields.BaseURL,
				JWTToken: tt.fields.JWTToken,
			}

			if tt.name == "Validate CreateUser with valid inputs" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}

			c.HTTPClient = tt.fields.HTTPClient
			_, err := c.CreateUser(tt.args.u)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.CreateUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_GetUsers(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []types.UserCreateResponse
		wantErr bool
	}{
		{
			name: "Validate GetUsers with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				name: "superadmin",
			},
			wantErr: false,
		},
		{
			name: "Validate GetUsers with NIL HTTPClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				name: "superadmin",
			},
			wantErr: true,
		},
		{
			name: "Validate GetUsers with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
		{
			name: "Validate GetUsers with Invalid client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
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

			if tt.name == "Validate GetUsers with Invalid client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}

			_, err := c.GetUsers(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetUsers() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_CreateRole(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"

	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		r types.RoleCreate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *types.RoleCreateResponse
		wantErr bool
	}{
		{
			name: "Validate CreateRole with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &ClientMock{},
			},
			wantErr: false,
		},
		{
			name:    "test_createrole - case 2",
			fields:  fields{},
			wantErr: true,
		},
		{
			name: "Validate CreateRole with NIL Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate CreateRole with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
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

			if tt.name == "Validate CreateRole with valid inputs" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.CreateRole(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.CreateRole() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_GetRoles(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		service         string
		name            string
		context         string
		contextContains string
		allContexts     bool
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    aasTypes.Roles
		wantErr bool
	}{
		{
			name: "Validate GetRoles with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate GetRoles with valid inputs with query parameters",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				service:         "CMS",
				name:            "CertApprover",
				context:         "CN=WLS TLS Certificate;SAN=wls.server.com,controller;certType=TLS",
				contextContains: "CN",
				allContexts:     true,
			},
			wantErr: false,
		},
		{
			name: "Validate GetRoles with NIL httpClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate GetRoles with Invalid Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			wantErr: true,
		},
		{
			name: "Validate GetRoles with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
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

			if tt.name == "Validate GetRoles with Invalid Client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.GetRoles(tt.args.service, tt.args.name, tt.args.context, tt.args.contextContains, tt.args.allContexts)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetRoles() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_DeleteRole(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		roleId string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate DeleteRole with invalid client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				roleId: "75fa8fe0-f2e0-436b-9cd3-ca3f4d1f9585",
			},
			wantErr: true,
		},
		{
			name: "Validate DeleteRole with NIL client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate DeleteRole with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(""),
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
			if err := c.DeleteRole(tt.args.roleId); (err != nil) != tt.wantErr {
				t.Errorf("Client.DeleteRole() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_GetPermissionsForUser(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		userID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []types.PermissionInfo
		wantErr bool
	}{
		{
			name: "Validate GetPermissionsForUser with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: false,
		},
		{
			name: "Validate GetPermissionsForUser with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate GetPermissionsForUser with NIL httpClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate GetPermissionsForUser with Invalid Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
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

			if tt.name == "Validate GetPermissionsForUser with Invalid Client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.GetPermissionsForUser(tt.args.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetPermissionsForUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_GetRolesForUser(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		userID string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []types.RoleInfo
		wantErr bool
	}{
		{
			name: "Validate GetRolesForUser with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: false,
		},
		{
			name: "Validate GetRolesForUser with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate GetRolesForUser with NIL HTTPClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate GetRolesForUser with Invalid client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
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

			if tt.name == "Validate GetRolesForUser with Invalid client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.GetRolesForUser(tt.args.userID)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetRolesForUser() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_UpdateUser(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		userID string
		user   types.UserCreate
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate UpdateUser with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: false,
		},
		{
			name: "Validate UpdateUser with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate UpdateUser with NIL client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate UpdateUser with Invalid client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
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
			if tt.name == "Validate UpdateUser with Invalid client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			if err := c.UpdateUser(tt.args.userID, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("Client.UpdateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_AddRoleToUser(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		userID string
		r      types.RoleIDs
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Validate AddRoleToUser with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: false,
		},
		{
			name: "Validate AddRoleToUser with invalid client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate AddRoleToUser with NIL HTTPClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			args: args{
				userID: "1fdb39de-7bf4-440e-ad05-286eca933f78",
			},
			wantErr: true,
		},
		{
			name: "Validate AddRoleToUser with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(token),
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
			if tt.name == "Validate AddRoleToUser with valid inputs" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			if err := c.AddRoleToUser(tt.args.userID, tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("Client.AddRoleToUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClient_GetCredentials(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		createCredentailsReq types.CreateCredentialsReq
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate GetCredentials with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			wantErr: false,
		},
		{
			name: "Validate GetCredentials with Invalid Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
		{
			name: "Validate GetCredentials with NIL Client",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate GetCredentials with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(""),
				HTTPClient: &http.Client{},
			},
			wantErr: true,
		},
		{
			name: "Validate GetCredentials with Invalid ComponentType",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			args: args{
				createCredentailsReq: types.CreateCredentialsReq{
					ComponentType: "test",
				},
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

			if tt.name == "Validate GetCredentials with valid inputs" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.GetCredentials(tt.args.createCredentailsReq)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_GetCustomClaimsToken(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	type args struct {
		customClaimsTokenReq types.CustomClaims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate GetCustomClaimsToken with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate GetCustomClaimsToken with NIL HTTPClient",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate GetCustomClaimsToken with Invalid JWT",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &ClientMock{},
			},
			wantErr: true,
		},
		{
			name: "Validate GetCustomClaimsToken with empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(""),
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

			if tt.name == "Validate GetCustomClaimsToken with Invalid JWT" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.GetCustomClaimsToken(tt.args.customClaimsTokenReq)
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetCustomClaimsToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestClient_GetJwtSigningCertificate(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		JWTToken   []byte
		HTTPClient HttpClient
	}
	tests := []struct {
		name    string
		fields  fields
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate GetJwtSigningCertificate with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				JWTToken:   []byte(token),
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate GetJwtSigningCertificate with Empty BaseURL",
			fields: fields{
				BaseURL:    "",
				JWTToken:   []byte(""),
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
			_, err := c.GetJwtSigningCertificate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Client.GetJwtSigningCertificate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
