/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"bytes"
	"encoding/json"

	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants" // Import the constants package
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"

	"io"
	"net/http"
)

// func getHostUUID() (string, error) {
// 	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
// 	if err != nil {
// 		logging.Error("error reading UUID: %v", err)
// 		return "", err
// 	}
// 	return strings.TrimSpace(string(uuid)), nil
// }

func AddHostToVerifier(cfg *constants.Config, token string, hostname string) (bool, string) {
	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}
	// hostName, err := getHostUUID()
	// if err != nil {
	// 	logging.Error("Error getting host UUID:", err)
	// }
	// hostName := os.Getenv("NODE_NAME")
	hostName := "tc-node"
	logging.Info("Host Name retrieved successfully:", hostName)
	type Payload struct {
		ConnectionString string   `json:"connection_string"`
		Description      string   `json:"description"`
		FlavorGroupNames []string `json:"flavorgroup_names"`
		HostName         string   `json:"host_name"`
	}
	data := Payload{
		ConnectionString: "intel:nats://tc-node",
		Description:      "TC Edge Device",
		FlavorGroupNames: []string{"automatic"},
		HostName:         hostName,
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("Error marshalling payload:", err)
		return false, ""
	}

	// Log the payload
	logging.Trace("Payload:", string(payloadBytes))

	body := bytes.NewReader(payloadBytes)
	url := cfg.HVSURL + ":" + cfg.HVSPort + "/hvs/v2/hosts"
	logging.Debug("Host registration URL:", url)
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logging.Error("Error creating new request:", err)
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	logging.Debug("Request Headers:", req.Header)
	logging.Debug("Request Body:", req.Body)
	// logging.Debug("Request URL:", req.URL)
	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Error making the request:", err)
		return false, ""
	}
	defer resp.Body.Close()

	logging.Trace("Response Status:", resp.Status)

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("Error reading the response body:", err)
		return false, ""
	}

	logging.Debug("Response Status:", resp.Status)
	// success, message := CheckResponseStatus(resp)
	// if !success {
	// 	logging.Debug("Response status:", resp.Status)
	// 	return false, fmt.Sprintf("Unexpected response status: %s %s", message, string(readval))
	// }

	logging.Trace("Response Body:", string(readval))

	return true, " "
}

func FetchHosts(cfg *constants.Config, token string) (bool, string) {
	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	url := cfg.HVSURL + ":" + cfg.HVSPort + "/hvs/v2/hosts"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logging.Error("Error creating request:", err)
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

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

	return true, string(readval)
}
