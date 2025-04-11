/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants" // Import the constants package
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

type FlavorPayload struct {
	ConnectionString   string   `json:"connection_string"`
	PartialFlavorTypes []string `json:"partial_flavor_types"`
	FlavorGroupNames   []string `json:"flavorgroup_names"`
}

func AddFlavorTemplate(cfg *constants.Config, token string, hostname string) (bool, string) {
	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	data := FlavorPayload{
		ConnectionString:   "intel:nats://tc-node",
		PartialFlavorTypes: []string{"PLATFORM", "OS", "IMA"},
		FlavorGroupNames:   []string{"automatic"},
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("Error marshalling payload:", err)
		return false, ""
	}
	logging.Trace("Payload:", string(payloadBytes))

	body := bytes.NewReader(payloadBytes)
	url := fmt.Sprintf("%s:%s/hvs/v2/flavors", cfg.HVSURL, cfg.HVSPort)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logging.Error("Error creating new request:", err)
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	logging.Trace("Request Headers:", req)
	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Error making the request:", err)
		return false, ""
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("Error reading the response body:", err)
		return false, ""
	}

	logging.Trace("Response Status:", resp.Status)
	logging.Trace("Response Body:", string(readval))
	success, message := CheckResponseStatus(resp)
	if !success {
		// logging.Error("Unexpected response status:", resp.Status)
		logging.Debug("Response status:", resp.Status)
		return false, fmt.Sprintf("Unexpected response status: %s %s", message, string(readval))
	}

	return true, " "
}

type Flavor struct {
	Meta struct {
		ID string `json:"id"`
	} `json:"meta"`
}

type FlavorsResponse struct {
	SignedFlavors []struct {
		Flavor Flavor `json:"flavor"`
	} `json:"signed_flavors"`
}

func GetFlavorIDs(cfg *constants.Config, bearerToken string) ([]string, error) {
	url := fmt.Sprintf("%s:%s/hvs/v2/flavors", cfg.HVSURL, cfg.HVSPort)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logging.Error("Error creating the request:", err)
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		logging.Error("error making the request: ", err)
		return nil, err
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("error reading the response body: ", err)
		return nil, err
	}

	var flavorsResponse FlavorsResponse
	err = json.Unmarshal(readval, &flavorsResponse)
	if err != nil {
		logging.Error("error unmarshalling the response: ", err)
		return nil, err
	}

	var flavorIDs []string
	for _, signedFlavor := range flavorsResponse.SignedFlavors {
		flavorIDs = append(flavorIDs, signedFlavor.Flavor.Meta.ID)
	}

	return flavorIDs, nil
}

func DeleteFlavor(cfg *constants.Config, flavorID, bearerToken string) (bool, string) {
	url := fmt.Sprintf("%s:%s/hvs/v2/flavors/%s", cfg.HVSURL, cfg.HVSPort, flavorID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		logging.Error("Error creating the request:", err)
		return false, ""
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Error making the request:", err)
		return false, ""
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("Error reading the response body:", err)
		return false, ""
	}

	logging.Trace("Response Status:", resp.Status)
	logging.Trace("Response Body:", string(readval))

	return true, string(readval)
}

func GetFlavor(cfg *constants.Config, bearerToken string) (bool, string) {
	url := fmt.Sprintf("%s:%s/hvs/v2/flavors", cfg.HVSURL, cfg.HVSPort)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logging.Error("error creating the request: ", err)
		return false, ""
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	resp, err := client.Do(req)
	if err != nil {
		logging.Error("error making the request: ", err)
		return false, ""
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("error reading the response body: %v", err)
		return false, ""
	}
	logging.Trace("Response Status:", resp.Status)
	logging.Trace("Response Body:", string(readval))

	return true, string(readval)
}
