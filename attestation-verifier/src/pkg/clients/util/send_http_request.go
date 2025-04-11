/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"crypto/x509"
	"io/ioutil"
	"net/http"
	"strconv"
	"sync"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"

	"github.com/pkg/errors"
)

var jwtTokenMap = sync.Map{}

var log = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

var httpClient *http.Client
var httpsClient *http.Client

func addJWTToken(aasClient *aas.JwtClient, req *http.Request, serviceUsername, servicePassword string, forceFetch bool) error {
	log.Trace("clients/send_http_request:addJWTToken() Entering")
	defer log.Trace("clients/send_http_request:addJWTToken() Leaving")

	var err error
	var jwtToken []byte
	token, ok := jwtTokenMap.Load(serviceUsername)
	if forceFetch || !ok {
		jwtToken, err = fetchJwtToken(aasClient, serviceUsername, servicePassword)
		if err != nil {
			return errors.Wrap(err, "clients/send_http_request.go:addJWTToken() Could not fetch token")
		}
		jwtTokenMap.Store(serviceUsername, jwtToken)
	} else {
		jwtToken = token.([]byte)
	}
	secLog.Debug("clients/send_http_request:addJWTToken() successfully added jwt bearer token")
	req.Header.Set("Authorization", "Bearer "+string(jwtToken))
	return nil
}

func fetchJwtToken(aasClient *aas.JwtClient, serviceUsername string, servicePassword string) ([]byte, error) {
	log.Trace("clients/send_http_request:fetchJwtToken() Entering")
	defer log.Trace("clients/send_http_request:fetchJwtToken() Leaving")

	aasClient.AddUser(serviceUsername, servicePassword)
	err := aasClient.FetchAllTokens()
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:fetchJwtToken() Could not fetch token")
	}
	jwtToken, err := aasClient.GetUserToken(serviceUsername)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:fetchJwtToken() Error retrieving token from cache")
	}
	return jwtToken, nil
}

//SendRequest method is used to create an http client object and send the request to the server
func SendRequest(req *http.Request, aasURL, serviceUsername, servicePassword string,
	trustedCaCerts []x509.Certificate) ([]byte, error) {
	log.Trace("clients/send_http_request:SendRequest() Entering")
	defer log.Trace("clients/send_http_request:SendRequest() Leaving")

	response, err := GetHTTPResponse(req, trustedCaCerts, true, aasURL, serviceUsername, servicePassword)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error getting response")
	}
	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendRequest() Error from response")
	}
	log.Debug("clients/send_http_request.go:SendRequest() Received the response successfully")
	return body, nil
}

//SendNoAuthRequest method is used to create an http client object and send the request to the server
func SendNoAuthRequest(req *http.Request, trustedCaCerts []x509.Certificate) ([]byte, error) {
	log.Trace("clients/send_http_request:SendNoAuthRequest() Entering")
	defer log.Trace("clients/send_http_request:SendNoAuthRequest() Leaving")

	response, err := GetHTTPResponse(req, trustedCaCerts, false)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendNoAuthRequest() Error getting response")
	}
	defer func() {
		derr := response.Body.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing response body")
		}
	}()

	//create byte array of HTTP response body
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:SendNoAuthRequest() Error from response")
	}
	log.Debug("clients/send_http_request.go:SendNoAuthRequest() Received the response successfully")
	return body, nil
}

//GetHTTPResponse method is used to create an http client object and send the request to the server
//cred param should have aasURL, serviceUsername, servicePassword in the said order
func GetHTTPResponse(req *http.Request, trustedCaCerts []x509.Certificate, addToken bool, cred ...string) (*http.Response, error) {
	log.Trace("clients/send_http_request:GetHTTPResponse() Entering")
	defer log.Trace("clients/send_http_request:GetHTTPResponse() Leaving")

	var err error
	var client aas.HttpClient
	//This has to be done for dynamic loading or unloading of certificates
	if len(trustedCaCerts) == 0 {
		if httpClient == nil {
			httpClient = clients.HTTPClientTLSNoVerify()
		}
		client = httpClient
	} else {
		if httpsClient == nil {
			httpsClient, _ = clients.HTTPClientWithCA(trustedCaCerts)
		}
		client = httpsClient
	}
	log.Debug("clients/send_http_request:SendNoAuthRequest() HTTP client successfully created")

	var aasClient *aas.JwtClient
	if addToken {
		aasClient = aas.NewJWTClient(cred[0])
		aasClient.HTTPClient = client
		log.Debug("clients/send_http_request:GetHTTPResponse() AAS client successfully created")

		err = addJWTToken(aasClient, req, cred[1], cred[2], false)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:GetHTTPResponse() Failed to add JWT token")
		}
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "clients/send_http_request.go:GetHTTPResponse() Error from response")
	}
	if response.StatusCode == http.StatusUnauthorized && addToken {
		// fetch token and try again
		err = addJWTToken(aasClient, req, cred[1], cred[2], true)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:GetHTTPResponse() Failed to add JWT token")
		}
		response, err = client.Do(req)
		if err != nil {
			return nil, errors.Wrap(err, "clients/send_http_request.go:GetHTTPResponse() Error from response")
		}
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusNoContent {
		return response, errors.Wrap(errors.New("HTTP Status :"+strconv.Itoa(response.StatusCode)),
			"clients/send_http_request.go:SendRequest() Error from response")
	}

	log.Debug("clients/send_http_request.go:GetHTTPResponse() Received the response successfully")
	return response, nil
}
