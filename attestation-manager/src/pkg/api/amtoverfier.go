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
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"   // Import the logging package
)

type Report struct {
	Reports []struct {
		ID               string `json:"id"`
		TrustInformation struct {
			OVERALL      bool `json:"OVERALL"`
			FlavorsTrust struct {
				OS struct {
					Trust bool `json:"trust"`
					Rules []struct {
						Rule struct {
							RuleName string   `json:"rule_name"`
							Markers  []string `json:"markers"`
						} `json:"rule"`
						FlavorID string `json:"flavor_id"`
						Trusted  bool   `json:"trusted"`
					} `json:"rules"`
				} `json:"OS"`
				PLATFORM struct {
					Trust bool `json:"trust"`
					Rules []struct {
						Rule struct {
							RuleName string   `json:"rule_name"`
							Markers  []string `json:"markers"`
						} `json:"rule"`
						FlavorID string `json:"flavor_id"`
						Trusted  bool   `json:"trusted"`
					} `json:"rules"`
				} `json:"PLATFORM"`
				IMA struct {
					Trust bool `json:"trust"`
					Rules []struct {
						Rule struct {
							RuleName          string   `json:"rule_name"`
							Markers           []string `json:"markers"`
							ExpectedIMAValues struct {
								IMAMeasurements []struct {
									File        string `json:"file"`
									Measurement string `json:"measurement"`
								} `json:"ima_measurements"`
							} `json:"expected_imavalues"`
						} `json:"rule"`
						FlavorID string `json:"flavor_id"`
						Trusted  bool   `json:"trusted"`
					} `json:"rules"`
				} `json:"IMA"`
			} `json:"flavors_trust"`
		} `json:"trust_information"`
		HostInfo struct {
			HardwareUUID     string `json:"hardware_uuid"`
			HardwareFeatures struct {
				UEFI struct {
					Enabled string `json:"enabled"`
					Meta    struct {
						SecureBootEnabled bool `json:"secure_boot_enabled"`
					} `json:"meta"`
				} `json:"UEFI"`
			} `json:"hardware_features"`
		} `json:"host_info"`
	} `json:"reports"`
}

func GenerateTrustReport(cfg *constants.Config, token string, hostname string) (bool, string) {

	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	// payload := map[string]string{"host_name": hostname}
	type Payload struct {
		HostName string `json:"host_name"`
	}
	data := Payload{
		HostName: hostname,
	}
	payloadBytes, err := json.Marshal(data)
	// jsonPayload, err := json.Marshal(payload)
	if err != nil {
		logging.Error("Error marshalling JSON payload:", err)
		return false, ""

	}
	logging.Trace("Payload for report:", string(payloadBytes))

	body := bytes.NewReader(payloadBytes)
	url := fmt.Sprintf("%s:%s/hvs/v2/reports", cfg.HVSURL, cfg.HVSPort)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		logging.Error("Error creating new request:", err)
		return false, ""
	}
	logging.Trace("Request Headers to Generate trust report:", req)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Error executing request to get report:", err)
		return false, ""
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("Error reading the response body:", err)
		return false, ""
	}

	logging.Trace("Response body for report:", string(readval))

	success, message := CheckResponseStatus(resp)
	if !success {
		// logging.Error("Unexpected response status:", resp.Status)
		logging.Debug("Response status:", resp.Status)
		return false, fmt.Sprintf("Unexpected response status: %s %s", message, string(readval))
	}

	// report = string(readval)
	return true, string(readval)
}

func FetchTrustReport(cfg *constants.Config, token string, hostname string) (bool, string) {
	report := ""
	var attest_report Report
	client, err := HTTPClientWithCA()
	if err != nil {
		logging.Error("Error creating HTTP client with CA:", err)
		return false, ""
	}

	url := fmt.Sprintf("%s:%s/hvs/v2/reports?hostName=%s&latestPerHost=true", cfg.HVSURL, cfg.HVSPort, hostname)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logging.Error("Error creating request:", err)
		return false, ""
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		logging.Error("Error executing request to get report:", err)
		return false, ""
	}
	defer resp.Body.Close()

	readval, err := io.ReadAll(resp.Body)
	if err != nil {
		logging.Error("Error reading the response body:", err)
		return false, ""
	}

	report = string(readval)
	jsonData := report
	attest_report_err := json.Unmarshal([]byte(jsonData), &attest_report)
	if attest_report_err != nil {
		logging.Error("Error parsing JSON:", err)
	}
	if len(attest_report.Reports) == 0 {
		logging.Info("No Trust reports found!!!")
		return false, ""
	}
	return true, report
}

func ParseTrustReport(readdata string) (bool, bool, string, string) {
	logging.Debug("Parsing report...")
	jsonData := readdata

	// Parse the JSON data into a Report struct
	var report Report

	// Declare variables to store secure boot status, UUID, and failure message
	var secureBootEnabled bool
	var HardwareGuid string
	var attestStatusMessage string

	// Declare a boolean variable to check the trust
	var check_trust bool = false
	err := json.Unmarshal([]byte(jsonData), &report)
	if err != nil {
		logging.Error("Error parsing JSON:", err)
		return false, false, "", "Error parsing JSON"
	}

	if len(report.Reports) == 0 {
		logging.Info("No reports found!!!")
		return false, false, "", "No reports found"
	}

	r := report.Reports[0]
	// Print the JSON report for debugging purposes
	logging.Debug("JSON Report:", jsonData)
	check_trust = false
	// Fetch secure_boot_enabled  status and HW UUID
	secureBootEnabled = r.HostInfo.HardwareFeatures.UEFI.Meta.SecureBootEnabled
	HardwareGuid = r.HostInfo.HardwareUUID
	logging.Debug("Secure Boot Enabled Status:", secureBootEnabled)
	logging.Debug("Hardware UUID:", HardwareGuid)

	logging.Debug(" Report ID:", r.ID)
	logging.Info("Overall Trust Status:", r.TrustInformation.OVERALL)

	if !r.TrustInformation.OVERALL {
		logging.Info("Overall trust is false, checking specific trust statuses...")

		logging.Info("OS trust:", r.TrustInformation.FlavorsTrust.OS.Trust)
		if !r.TrustInformation.FlavorsTrust.OS.Trust {
			logging.Info("OS trust verification failed.")
			attestStatusMessage = "OS trust verification failed"
		}

		logging.Info("IMA trust:", r.TrustInformation.FlavorsTrust.IMA.Trust)
		if !r.TrustInformation.FlavorsTrust.IMA.Trust {
			logging.Info("IMA trust verification failed.")
			attestStatusMessage = "IMA trust verification failed"
		}

		logging.Info("PLATFORM trust:", r.TrustInformation.FlavorsTrust.PLATFORM.Trust)
		if !r.TrustInformation.FlavorsTrust.PLATFORM.Trust {
			logging.Info("PLATFORM trust verification failed.")
			attestStatusMessage = "PLATFORM trust verification failed"
		}
		logging.Info("Trust verification failed, notify the Kubernetes API to cordon the node")
	} else {
		logging.Info("Overall trust is true.")
		attestStatusMessage = "Attestation successful"
		check_trust = true
	}

	return check_trust, secureBootEnabled, HardwareGuid, attestStatusMessage
}
