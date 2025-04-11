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
	"os"

	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

func GetAttestToken(cfg *constants.Config) (bool, string) {
	token := `nil`

	username := os.Getenv("AAS_USERNAME")
	password := os.Getenv("AAS_PASSWORD")

	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	logging.Trace("client:", client)

	type Payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	data := Payload{
		Username: username,
		Password: password,
	}
	payloadBytes, err := json.Marshal(data)
	if err != nil {
		logging.Error("Error marshalling payload:", err)
		return false, ""
	}
	body := bytes.NewReader(payloadBytes)
	url := fmt.Sprintf("%s:%s/aas/v1/token", cfg.AASURL, cfg.AASPort)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logging.Error("Error creating new request:", err)
		return false, ""
	}
	req.Header.Set("Content-Type", "application/json")
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
	token = string(readval)
	return true, token
}
