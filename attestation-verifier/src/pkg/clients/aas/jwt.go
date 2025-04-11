/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package aas

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
)

type JWTClientErr struct {
	ErrMessage string
	ErrInfo    string
}

func (ucErr *JWTClientErr) Error() string {
	return fmt.Sprintf("%s: %s", ucErr.ErrMessage, ucErr.ErrInfo)
}

var (
	ErrHTTPGetJWTCert = &clients.HTTPClientErr{
		ErrMessage: "Failed to retrieve JWT signing certificate",
	}
	ErrHTTPFetchJWTToken = &clients.HTTPClientErr{
		ErrMessage: "Failed to retrieve JWT token from aas",
	}
	ErrUserNotFound = &JWTClientErr{
		ErrMessage: "User name not registered",
		ErrInfo:    "",
	}
	ErrJWTNotYetFetched = &JWTClientErr{
		ErrMessage: "User token not yet fetched",
		ErrInfo:    "",
	}
)

type JwtClient struct {
	BaseURL    string
	HTTPClient HttpClient

	users  map[string]*types.UserCred
	tokens map[string][]byte
}

func NewJWTClient(url string) *JwtClient {

	ret := JwtClient{BaseURL: url}
	ret.users = make(map[string]*types.UserCred)
	ret.tokens = make(map[string][]byte)
	return &ret
}

func (c *JwtClient) AddUser(username, password string) {
	c.users[username] = &types.UserCred{
		UserName: username,
		Password: password,
	}
}

func (c *JwtClient) GetUserToken(username string) ([]byte, error) {
	if _, ok := c.users[username]; !ok {
		ErrUserNotFound.ErrInfo = username
		return nil, ErrUserNotFound
	}
	token, ok := c.tokens[username]
	if ok {
		return token, nil
	}
	ErrJWTNotYetFetched.ErrInfo = username
	return nil, ErrJWTNotYetFetched
}

func (c *JwtClient) FetchAllTokens() error {

	for user, userCred := range c.users {
		token, err := c.fetchToken(userCred)
		if err != nil {
			return err
		}
		c.tokens[user] = token
	}
	return nil
}

func (c *JwtClient) FetchTokenForUser(username string) ([]byte, error) {

	userCred, ok := c.users[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	token, err := c.fetchToken(userCred)
	if err != nil {
		return nil, err
	}
	c.tokens[username] = token
	return token, nil
}

//Fetch custom claims token using JWT
func (c *JwtClient) FetchCCTUsingJWT(bearerToken string, customClaims types.CustomClaims) ([]byte, error) {

	var err error

	customClaimsUrl := clients.ResolvePath(c.BaseURL, "custom-claims-token")
	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(customClaims)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodPost, customClaimsUrl, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/jwt")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	if c.HTTPClient == nil {
		return nil, errors.New("clients/aas/jwt: FetchCCTUsingJWT() HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPFetchJWTToken.RetCode = rsp.StatusCode
		return nil, ErrHTTPFetchJWTToken
	}
	jwtToken, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return jwtToken, nil
}

func (c *JwtClient) fetchToken(userCred *types.UserCred) ([]byte, error) {

	var err error

	jwtUrl := clients.ResolvePath(c.BaseURL, "token")
	buf := new(bytes.Buffer)
	err = json.NewEncoder(buf).Encode(userCred)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest(http.MethodPost, jwtUrl, buf)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/jwt")

	if c.HTTPClient == nil {
		return nil, errors.New("jwtClient.fetchToken: HTTPClient should not be null")
	}
	rsp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if rsp.StatusCode != http.StatusOK {
		ErrHTTPFetchJWTToken.RetCode = rsp.StatusCode
		return nil, ErrHTTPFetchJWTToken
	}
	jwtToken, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}
	return jwtToken, nil
}
