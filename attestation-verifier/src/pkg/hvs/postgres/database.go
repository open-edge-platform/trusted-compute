/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/pkg/errors"
)

func InitDatabase(cfg *commConfig.DBConfig) (*DataStore, error) {
	defaultLog.Trace("postgres/database:InitDatabase() Entering")
	defer defaultLog.Trace("postgres/database:InitDatabase() Leaving")

	// Create conf for DBTypePostgres
	conf := Config{
		Vendor:            constants.DBTypePostgres,
		Host:              cfg.Host,
		Port:              cfg.Port,
		User:              cfg.Username,
		Password:          cfg.Password,
		Dbname:            cfg.DBName,
		SslMode:           cfg.SSLMode,
		SslCert:           cfg.SSLCert,
		ConnRetryAttempts: cfg.ConnectionRetryAttempts,
		ConnRetryTime:     cfg.ConnectionRetryTime,
	}

	// Creates a DBTypePostgres DB instance
	dataStore, err := NewDataStore(&conf)
	if err != nil {
		return nil, errors.Wrap(err, "Error instantiating Database")
	}
	defaultLog.Info("Migrating Database")
	dataStore.Migrate()

	return dataStore, nil
}

func NewDataStore(config *Config) (*DataStore, error) {
	if config.Vendor == constants.DBTypePostgres {
		return New(config)
	}
	return nil, errors.Errorf("Unsupported database vendor")
}
