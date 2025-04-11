/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"os"
)

func main() {

	fmt.Println("Starting database migration for hvs pagination")

	//Fetching configuration details
	config, err := config.LoadConfiguration()
	if err != nil {
		fmt.Println("Error in loading config")
		os.Exit(1)
	}

	dbConf := config.DB

	dataStore, err := postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &dbConf))
	if err != nil {
		fmt.Println("Error in establishing database connection")
		os.Exit(1)
	}

	// Executing query for tables
	tablesToAlter := [...]string{"host", "host_status", "report", "flavor", "flavor_group", "esxi_cluster", "tpm_endorsement", "audit_log_entry"}
	for _, t := range tablesToAlter {
		sqlCmd := "alter table " + t + " add column rowid serial unique"
		err = dataStore.ExecuteSql(&sqlCmd)
		if err != nil {
			fmt.Println("Error in executing query " + sqlCmd + err.Error())
			os.Exit(1)
		}
	}
	fmt.Println("DB migration successful")
}
