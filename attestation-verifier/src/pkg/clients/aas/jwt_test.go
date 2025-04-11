/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"net/http"
	"testing"

	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

func TestJWTClientErrError(t *testing.T) {
	type fields struct {
		ErrMessage string
		ErrInfo    string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Validate Error with different error messages",
			fields: fields{
				ErrMessage: "Error in initializing jwt client",
				ErrInfo:    "There is an 400 error",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ucErr := &JWTClientErr{
				ErrMessage: tt.fields.ErrMessage,
				ErrInfo:    tt.fields.ErrInfo,
			}
			ucErr.Error()
		})
	}
}

func TestNewJWTClient(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name string
		args args
		want *JwtClient
	}{
		{
			name: "Validate NewJWTClient - valid case",
			args: args{
				url: "https://localhost:8771/",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewJWTClient(tt.args.url)
		})
	}
}

func TestJwtClientAddUser(t *testing.T) {
	type fields struct {
		BaseURL    string
		HTTPClient *http.Client
		users      map[string]*types.UserCred
		tokens     map[string][]byte
	}
	type args struct {
		username string
		password string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "Validate AddUser with valid user name and password",
			fields: fields{
				BaseURL:    "https://localhost:8771/",
				HTTPClient: &http.Client{},
				users:      make(map[string]*types.UserCred),
				tokens:     make(map[string][]byte),
			},
			args: args{
				username: "admin",
				password: "password",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JwtClient{
				BaseURL:    tt.fields.BaseURL,
				HTTPClient: tt.fields.HTTPClient,
				users:      tt.fields.users,
				tokens:     tt.fields.tokens,
			}
			c.AddUser(tt.args.username, tt.args.password)
		})
	}
}

func TestJwtClientGetUserToken(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		HTTPClient *http.Client
		users      map[string]*types.UserCred
		tokens     map[string][]byte
	}
	type args struct {
		username string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate GetUserToken with valid users",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
				users:      make(map[string]*types.UserCred),
				tokens:     make(map[string][]byte),
			},
			args: args{
				username: "admin",
			},
			wantErr: false,
		},
		{
			name: "Validate GetUserToken with Invalid users",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
				users:      make(map[string]*types.UserCred),
				tokens:     make(map[string][]byte),
			},
			args: args{
				username: "admin",
			},
			wantErr: true,
		},
		{
			name: "Validate GetUserToken with NIL users",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
				users:      make(map[string]*types.UserCred),
				tokens:     make(map[string][]byte),
			},
			args: args{
				username: "admin",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JwtClient{
				BaseURL:    tt.fields.BaseURL,
				HTTPClient: tt.fields.HTTPClient,
				users:      tt.fields.users,
				tokens:     tt.fields.tokens,
			}
			if tt.name == "Validate GetUserToken with valid users" {
				c.AddUser("admin", "password")
				c.FetchTokenForUser("admin")
			} else if tt.name == "Validate GetUserToken with Invalid users" {
				c.AddUser("admin", "password")
			}
			_, err := c.GetUserToken(tt.args.username)
			if (err != nil) != tt.wantErr {
				t.Errorf("JwtClient.GetUserToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestJwtClientFetchAllTokens(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		HTTPClient *http.Client
		users      map[string]*types.UserCred
		tokens     map[string][]byte
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate FetchAllTokens with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
				users:      make(map[string]*types.UserCred),
				tokens:     make(map[string][]byte),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JwtClient{
				BaseURL:    tt.fields.BaseURL,
				HTTPClient: tt.fields.HTTPClient,
				users:      tt.fields.users,
				tokens:     tt.fields.tokens,
			}
			c.AddUser("admin", "password")
			c.FetchTokenForUser("admin")
			if err := c.FetchAllTokens(); (err != nil) != tt.wantErr {
				t.Errorf("JwtClient.FetchAllTokens() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestJwtClientFetchCCTUsingJWT(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"

	type fields struct {
		BaseURL    string
		HTTPClient HttpClient
		users      map[string]*types.UserCred
		tokens     map[string][]byte
	}
	type args struct {
		bearerToken  string
		customClaims types.CustomClaims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate FetchCCTUsingJWT with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate FetchCCTUsingJWT with NIL Client",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate FetchCCTUsingJWT with Invalid client",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &ClientMock{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JwtClient{
				BaseURL:    tt.fields.BaseURL,
				HTTPClient: tt.fields.HTTPClient,
				users:      tt.fields.users,
				tokens:     tt.fields.tokens,
			}
			if tt.name == "Validate FetchCCTUsingJWT with Invalid client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.FetchCCTUsingJWT(tt.args.bearerToken, tt.args.customClaims)
			if (err != nil) != tt.wantErr {
				t.Errorf("JwtClient.FetchCCTUsingJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestJwtClientFetchToken(t *testing.T) {
	server := mockServer(t)
	defer server.Close()

	urlPath := server.URL + "/aas/v1"
	type fields struct {
		BaseURL    string
		HTTPClient HttpClient
		users      map[string]*types.UserCred
		tokens     map[string][]byte
	}
	type args struct {
		userCred *types.UserCred
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Validate fetchToken with valid inputs",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &http.Client{},
			},
			wantErr: false,
		},
		{
			name: "Validate fetchToken with NIL client",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: nil,
			},
			wantErr: true,
		},
		{
			name: "Validate fetchToken with Invalid client",
			fields: fields{
				BaseURL:    urlPath,
				HTTPClient: &ClientMock{},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JwtClient{
				BaseURL:    tt.fields.BaseURL,
				HTTPClient: tt.fields.HTTPClient,
				users:      tt.fields.users,
				tokens:     tt.fields.tokens,
			}

			if tt.name == "Validate fetchToken with Invalid client" {
				mock := NewClientMock()
				c.HTTPClient = mock
			}
			_, err := c.fetchToken(tt.args.userCred)
			if (err != nil) != tt.wantErr {
				t.Errorf("JwtClient.fetchToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
