/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package database

import (
	"encoding/json"
	"fmt"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	hvsconfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/upgrades/hvs/db/src/flavor-template/model"
	"gorm.io/gorm"
)

var Db *postgres.DataStore

// DownloadOldFlavors downloads flavor from postgres DB
func DownloadOldFlavors(cfg *hvsconfig.DBConfig, db *gorm.DB) ([]model.SignedFlavors, error) {

	fmt.Println("Downloading old flavors from database")

	var content string
	var signature string

	row, err := db.Raw(`SELECT id,content,signature from "flavor"`).Rows()
	if err != nil {
		fmt.Println("pgdb: failed to execute sql")
		return nil, err
	}
	defer row.Close()

	signedFlavors := []model.SignedFlavors{}

	for row.Next() {
		sf := model.SignedFlavors{}
		err = row.Scan(&sf.Flavor.Meta.ID, &content, &signature)
		if err != nil {
			fmt.Println("Error in Download Flavors : ", err)
			return nil, err
		}

		err = json.Unmarshal([]byte(content), &sf.Flavor)
		if err != nil {
			fmt.Println("Error in Download Flavors : ", err)
			return nil, err
		}
		sf.Signature = signature
		signedFlavors = append(signedFlavors, sf)
	}

	if len(signedFlavors) <= 0 {
		return nil, nil
	}
	fmt.Println("Downloading old flavors from database is successful")
	return signedFlavors, nil
}

// UpdateFlavor updates flavor table with converted flavor and signature
func UpdateFlavor(cfg *hvsconfig.DBConfig, db *gorm.DB, id uuid.UUID, flavor hvs.Flavor, signature string) error {

	updateStmt := `update "flavor" set "content"=$1, "signature"=$2 where "id"=$3`
	updateResponse := db.Exec(updateStmt, postgres.PGFlavorContent(flavor), signature, id)
	err := updateResponse.Error
	if err != nil {
		fmt.Println("Failed to update flavors to DB :", err)
		return err
	}

	fmt.Printf("\nUpdating converted %s Flavor back into database is successful", flavor.Meta.Description["flavor_part"])
	return nil
}

// GetDatabaseConnection returns a postgres.DataStore instance if establishing connection to Postgres DB is successful
func GetDatabaseConnection(cfg *hvsconfig.DBConfig) (*postgres.DataStore, error) {
	db, dbErr := postgres.InitDatabase(cfg)
	if dbErr != nil {
		fmt.Println("Error in establishing connection to Db")
		return nil, dbErr
	}
	return db, nil
}
