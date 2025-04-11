/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package main

import (
	"fmt"
	"os"
	"time"

	attestationstatusnmgr_sb "github.com/open-edge-platform/infra-managers/attestationstatus/pkg/api/attestmgr/v1"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/api"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-manager/src/pkg/logging"
)

func main() {

	// Load configuration
	cfg, err := constants.LoadConfig()
	if err != nil {
		logging.Error("Error loading configuration: %v", err)
	}
	retryCount := 10
	retryInterval := 60 * time.Second
	pollduration := cfg.POLLDURATION
	logging.Info("**********Attestation Manager Starts***********")

	var informedAMServer bool = false

	// Fetching the Bearer token
	getAttestTokenOperation := func() (bool, interface{}) {
		return api.GetAttestToken(cfg)
	}
	success, tokenResponse := retryOperation(getAttestTokenOperation, retryCount, retryInterval)
	attestToken, ok := tokenResponse.(string)
	if !success || !ok {
		logging.Error("Unable to fetch the token after retries!!!")
		return
	} else {
		logging.Info("Step 1 : Token retrieved successfully!")
	}

	// Adding host
	hostName := cfg.TCHOSTNAME
	logging.Info("Host name for registring to verifier:", hostName)

	addHostOperation := func() (bool, interface{}) {
		return api.AddHostToVerifier(cfg, attestToken, hostName)
	}
	success, response := retryOperation(addHostOperation, retryCount, retryInterval)

	if !success {
		logging.Error("Failed to add host -", response)
		return
	} else {
		logging.Info("step 2: Host added successfully:", response)
	}

	// Fetching Hosts
	success, hosts := api.FetchHosts(cfg, attestToken)
	if !success {
		logging.Error("Failed to fetch hosts")
	} else {
		logging.Info("Hosts fetched successfully:", hosts)
	}

	// Fetching Flavor IDs
	flavorIDs, err := api.GetFlavorIDs(cfg, attestToken)
	if err != nil {
		logging.Error("Error fetching flavor IDs:", err)
	}

	addFlavorTemplateOperation := func() (bool, interface{}) {
		flavorUpdateFilePath := cfg.FlavorUpdateFilePath // Path to the host file inside the container
		logging.Info("Host file path for flavor update check:", flavorUpdateFilePath)
		if _, err := os.Stat(flavorUpdateFilePath); err == nil {
			logging.Info("Flavors exists, skipping AddFlavorTemplate operation")
			return true, "Flavors exists, AddFlavorTemplate operation skipped"
		} else if os.IsNotExist(err) {
			logging.Info("Host file path for flavor update check does not exist, proceeding with exisiting flavor deletion")
			// Deleting Flavor IDs if existed
			for _, flavorID := range flavorIDs {
				logging.Info("Step 3: Deleting Existing flavor:", flavorID)
				success, response := api.DeleteFlavor(cfg, flavorID, attestToken)
				if success {
					logging.Info("Successfully deleted existing flavor:", flavorID)
				} else {
					logging.Error("Failed to delete flavor:", flavorID, "Response:", response)
				}
			}
			// Proceed with adding flavor template after deletion
			success, response := api.AddFlavorTemplate(cfg, attestToken, hostName)
			if success {
				logging.Info("Writing flavor status to  host file as AddFlavorTemplate succeeded")
				err := os.WriteFile(flavorUpdateFilePath, []byte("Flavor Templated added to Verifier\n"), 0644)
				if err != nil {
					logging.Error("Failed to write flavor status to host file:", err)
					return false, err
				}
				logging.Info("File successfully written to host path:", flavorUpdateFilePath)
				return success, response
			} else {
				logging.Error("Failed to add flavor template:", response)
				return false, response
			}
		} else {
			logging.Error("Error checking flavor file:", err)
			return false, err
		}
	}

	success, flavorResponse := retryOperation(addFlavorTemplateOperation, retryCount, retryInterval)

	if !success {
		logging.Error("Failed to add Flavor to verifier:", flavorResponse)
		return
	} else {
		logging.Info("Step 4: Add Flavor template to verifier result:", flavorResponse)
	}

	// Infinite loop for attestation verification
	for {
		// Fetching the Bearer token
		success, tokenResponse = retryOperation(getAttestTokenOperation, retryCount, retryInterval)
		attestToken, ok = tokenResponse.(string)
		if !success || !ok {
			logging.Error("Unable to fetch the token after retries!!!")
			return
		} else {
			logging.Info("Token retrieved successfully!")
		}

		// Retry logic for generating the trust report
		generateTrustReportOperation := func() (bool, interface{}) {
			return api.GenerateTrustReport(cfg, attestToken, hostName)
		}
		success, _ := retryOperation(generateTrustReportOperation, retryCount, retryInterval)
		if !success {
			logging.Error("Unable to generate the trust report after retries")
			return
		} else {
			logging.Info("Step 5: Trust report created successfully for verification of trust status")
		}

		// Retry logic for fetching the trust report
		fetchTrustReportOperation := func() (bool, interface{}) {
			return api.FetchTrustReport(cfg, attestToken, hostName)
		}
		success, attestReportInterface := retryOperation(fetchTrustReportOperation, retryCount, retryInterval)
		if !success {
			logging.Error("Unable to fetch the report after retries")
			return
		} else {
			logging.Info("Step 6: Trust report fetched successfully for verification of trust status")
		}

		// Parse the report
		attestReport, ok := attestReportInterface.(string)
		if !ok {
			logging.Error("Invalid attest report type. Expected string.")
			continue
		}
		parseSuccess, secureBootStatus, hardwareGuid, attestStatus := api.ParseTrustReport(attestReport)
		logging.Debug("Parse success status:", parseSuccess, "SecureBoot of Node:", secureBootStatus, "Hardware Details:", hardwareGuid, "Attestation Status:", attestStatus)
		logging.Info("Parse success status:", parseSuccess)
		if !secureBootStatus {
			logging.Info("SecureBoot Disabled, Informing Attestation Manager Server")
			var attestationDetails string = "SecureBoot Disabled"
			message, err := api.InformToAttestationManagerServer(cfg, attestationstatusnmgr_sb.AttestationStatus(2), hardwareGuid, attestationDetails)
			if err != nil {
				logging.Error(fmt.Sprintf("Failed to inform Attestation  Manager Server service: %v", err))
			} else {
				logging.Info(fmt.Sprintf("Successfully informed Attestation  Manager Server service: %s", message))
			}
		}
		if !parseSuccess {

			// var attestationDetails string = "Attestation Fail"
			message, err := api.InformToAttestationManagerServer(cfg, attestationstatusnmgr_sb.AttestationStatus(2), hardwareGuid, attestStatus)
			if err != nil {
				logging.Error(fmt.Sprintf("Failed to inform Attestation  Manager Server service: %v", err))
			} else {
				logging.Info(fmt.Sprintf("Successfully informed Attestation  Manager Server service: %s", message))
			}
			cordonDrainNode()
		} else {
			logging.Info("Step 7: Trust report parsed successfully")

			if !informedAMServer {
				// Inform Attestation  Manager Server Server on successful attestation first time
				message, err := api.InformToAttestationManagerServer(cfg, attestationstatusnmgr_sb.AttestationStatus(1), hardwareGuid, attestStatus)
				if err != nil {
					logging.Error(fmt.Sprintf("Failed to inform Attestation  Manager Server service: %v", err))
				} else {
					logging.Info(fmt.Sprintf("Successfully informed Attestation  Manager Server service: %s", message))
					informedAMServer = true
				}
			}
		}

		logging.Info("Attestation Manager running")
		logging.Info(fmt.Sprintf("Poll duration for %v minute to fetch report on next iteration", pollduration))
		time.Sleep(time.Duration(pollduration) * time.Minute)
		logging.Info("*********End of Attestation Verification*********")
	}
}

func retryOperation(operation func() (bool, interface{}), retryCount int, retryInterval time.Duration) (bool, interface{}) {
	for i := 0; i < retryCount; i++ {
		success, response := operation()
		if success {
			return true, response
		}
		if i < retryCount-1 {
			logging.Info(fmt.Sprintf("Retrying operation in %v seconds...", retryInterval.Seconds()))
			time.Sleep(retryInterval)
		} else {
			logging.Error("Exceeded maximum retries for operation")
		}
	}
	return false, nil
}

func cordonDrainNode() {
	logging.Info("Attestation failure, cordoning the node")
	logging.Debug("Sleeping for 30 seconds and calling drainNode()")
	time.Sleep(30 * time.Second)
	success := api.CordonAndDrainNode()
	if !success {
		logging.Error("Failed to cordon node")
	} else {
		logging.Info("Step 7: Node cordoned successfully on attestation failure")
	}
}
