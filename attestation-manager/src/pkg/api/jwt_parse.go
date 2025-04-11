/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"fmt"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func parseJWTPayload(jwtToken string) (map[string]interface{}, error) {
	token, _, err := jwt.NewParser().ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing JWT token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("error asserting JWT claims as map")
	}

	payloadData := make(map[string]interface{})
	for key, value := range claims {
		payloadData[key] = value
	}

	return payloadData, nil
}

func extractJwtPayloadData(jwtToken string) string {
	var attestNode string

	// Read file from the path passed from jwtToken
	fileContent, err := os.ReadFile(jwtToken)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return ""
	}
	jwtToken = string(fileContent)

	payload, err := parseJWTPayload(jwtToken)
	if err != nil {
		fmt.Printf("Error parsing JWT payload: %v\n", err)
		return ""
	}

	if iss, ok := payload["iss"]; ok {
		issStr := fmt.Sprintf("%v", iss)
		parts := strings.Split(issStr, "/")
		if len(parts) > 2 {
			// Work around for the Keycloak issuer URL
			// Replace "keycloak" with "attest-node" in the issuer URL
			// and use the last part as the attestNode
			attestNode = strings.Replace(parts[2], "keycloak", "attest-node", 1)
			fmt.Printf("FQDN generated: %s\n", attestNode)
		} else {
			fmt.Println("attestNode data not found in issuer")
		}
	} else {
		fmt.Println("Issuer not found in payload")
	}

	return attestNode
}
