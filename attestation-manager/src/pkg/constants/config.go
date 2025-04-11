/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

import (
	"fmt"
	"net/url"
	"os"
	"strconv"

	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

// Config struct holds the configuration values
type Config struct {
	AASURL                          string
	AASPort                         string
	AASUsername                     string
	AASPassword                     string
	CMSURL                          string
	CMSPort                         string
	HVSURL                          string
	HVSPort                         string
	HOSTNAME                        string
	NodeAgentCertPath               string
	CMSCertPath                     string
	OrchestratorCertPath            string
	FlavorUpdateFilePath            string
	AttestationManagerServerAddress string
	AttestationManagerServerPort    string
	TCHOSTNAME                      string
	POLLDURATION                    int
}

// LoadConfig loads the configuration from environment variables
func LoadConfig() (*Config, error) {
	// Initialize the config with default values
	config := &Config{
		NodeAgentCertPath:    "/mnt/access_token",
		CMSCertPath:          "/mnt/cms-ca-cert.pem",
		OrchestratorCertPath: "/mnt/orch-ca.crt",
		FlavorUpdateFilePath: "/temp/attestation_mgr/flavor_update",
	}

	// Map environment variables to config fields
	envVars := map[string]*string{
		"AAS_URL":                            &config.AASURL,
		"AAS_PORT":                           &config.AASPort,
		"AAS_USERNAME":                       &config.AASUsername,
		"AAS_PASSWORD":                       &config.AASPassword,
		"CMS_URL":                            &config.CMSURL,
		"CMS_PORT":                           &config.CMSPort,
		"HVS_URL":                            &config.HVSURL,
		"HVS_PORT":                           &config.HVSPort,
		"HOSTNAME":                           &config.HOSTNAME,
		"Attestation_Manager_SERVER_ADDRESS": &config.AttestationManagerServerAddress,
		"Attestation_Manager_SERVER_PORT":    &config.AttestationManagerServerPort,
		"TCHOSTNAME":                         &config.TCHOSTNAME,
	}

	// Handle POLLDURATION separately as it requires conversion
	pollDurationStr := os.Getenv("POLL_DURATION")
	if pollDurationStr == "" {
		logging.Error("Missing required environment variable: POLL_DURATION")
		return nil, fmt.Errorf("missing required environment variable: POLL_DURATION")
	}
	pollDuration, err := strconv.Atoi(pollDurationStr)
	if err != nil {
		logging.Error(fmt.Sprintf("Invalid POLL_DURATION value: %v", err))
		return nil, fmt.Errorf("invalid POLL_DURATION value: %v", err)
	}
	config.POLLDURATION = pollDuration

	// Check for missing environment variables
	missingVars := []string{}
	for key, value := range envVars {
		*value = os.Getenv(key)
		if *value == "" && key != "Attestation_Manager_SERVER_ADDRESS" {
			missingVars = append(missingVars, key)
		}
	}

	// If there are missing variables, log and return an error
	if len(missingVars) > 0 {
		logging.Error(fmt.Sprintf("Missing required environment variables: %v", missingVars))
		return nil, fmt.Errorf("missing required environment variables: %v", missingVars)
	}

	// Validate URLs
	urlVars := []string{config.AASURL, config.CMSURL, config.HVSURL}
	for _, rawURL := range urlVars {
		parsedURL, err := url.Parse(rawURL)
		if err != nil || parsedURL.Scheme != "https" || parsedURL.Host == "" {
			logging.Error(fmt.Sprintf("Invalid URL format: %s", rawURL))
			return nil, fmt.Errorf("invalid URL format: %s", rawURL)
		}
	}

	// Validate ports
	portVars := []string{config.AASPort, config.CMSPort, config.HVSPort}
	for _, portStr := range portVars {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 8000 || port > 65535 {
			logging.Error(fmt.Sprintf("Invalid port: %s", portStr))
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
	}

	// Return the loaded config
	return config, nil
}
