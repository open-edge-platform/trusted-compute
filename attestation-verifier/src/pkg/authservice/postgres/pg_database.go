/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"

	"github.com/pkg/errors"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var defaultLog = commLog.GetDefaultLogger()
var secLog = commLog.GetSecurityLogger()

type Config struct {
	Vendor, Host, Dbname, User, Password, SslMode, SslCert string
	Port, ConnRetryAttempts, ConnRetryTime                 int
}

func InitDatabase(cfg *commConfig.DBConfig) (*PostgresDatabase, error) {
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
	err = dataStore.Migrate()
	if err != nil {
		return nil, errors.Wrap(err, "Error migrating Database")
	}
	return dataStore, nil
}

func NewDataStore(config *Config) (*PostgresDatabase, error) {
	if config.Vendor == constants.DBTypePostgres {
		return New(config)
	}
	return nil, errors.Errorf("Unsupported database vendor")
}

func NewDatabaseConfig(vendor string, dbConfig *commConfig.DBConfig) *Config {
	return &Config{
		Vendor:            vendor,
		Host:              dbConfig.Host,
		Port:              dbConfig.Port,
		User:              dbConfig.Username,
		Password:          dbConfig.Password,
		Dbname:            dbConfig.DBName,
		SslMode:           dbConfig.SSLMode,
		SslCert:           dbConfig.SSLCert,
		ConnRetryAttempts: dbConfig.ConnectionRetryAttempts,
		ConnRetryTime:     dbConfig.ConnectionRetryTime,
	}
}

type PostgresDatabase struct {
	Db *gorm.DB
}

// New returns a DataStore instance with the gorm.DB set with the postgres
func New(cfg *Config) (*PostgresDatabase, error) {
	defaultLog.Trace("postgres/postgres:New() Entering")
	defer defaultLog.Trace("postgres/postgres:New() Leaving")

	var store PostgresDatabase

	if cfg.Host == "" || cfg.Port == 0 || cfg.User == "" ||
		cfg.Password == "" || cfg.Dbname == "" {
		err := errors.Errorf("postgres/postgres:New() All fields must be set (%s)", spew.Sdump(cfg))
		defaultLog.Error(err)
		secLog.Warningf("%s: Failed to connect to db, missing configuration - %s", commLogMsg.BadConnection, err)
		return nil, err
	}

	if cfg.Port > 65535 || cfg.Port <= 1024 {
		return nil, errors.New("Invalid or reserved port")
	}

	cfg.SslMode = strings.TrimSpace(strings.ToLower(cfg.SslMode))
	if cfg.SslMode != constants.SslModeAllow && cfg.SslMode != constants.SslModePrefer &&
		cfg.SslMode != constants.SslModeVerifyCa && cfg.SslMode != constants.SslModeRequire {
		cfg.SslMode = constants.SslModeVerifyFull
	}

	var sslCertParams string
	if cfg.SslMode == "verify-ca" || cfg.SslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + cfg.SslCert
	}

	var db *gorm.DB
	var dbErr error
	numAttempts := cfg.ConnRetryAttempts
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		cfg.Host, cfg.Port, cfg.User, cfg.Dbname, cfg.Password, cfg.SslMode, sslCertParams)

	if numAttempts < 0 || numAttempts > 100 {
		numAttempts = constants.DefaultDbConnRetryAttempts
	}

	for i := 0; i < numAttempts; i = i + 1 {
		retryTime := time.Duration(cfg.ConnRetryTime)

		db, dbErr = gorm.Open(postgres.Open(dsn), &gorm.Config{FullSaveAssociations: true,})
		if dbErr != nil {
			defaultLog.WithError(dbErr).Infof("postgres/postgres:New() Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}

		if retryTime < 0 || retryTime > 100 {
			retryTime = constants.DefaultDbConnRetryTime
		}
		time.Sleep(retryTime * time.Second)
	}

	if dbErr != nil {
		defaultLog.WithError(dbErr).Infof("postgres/postgres:New() Failed to connect to db after %d attempts\n", numAttempts)
		secLog.Warningf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, errors.Wrapf(dbErr, "Failed to connect to db after %d attempts", numAttempts)
	}

	store.Db = db
	return &store, nil
}

func (pd *PostgresDatabase) ExecuteSql(sql *string) error {
	defaultLog.Trace("ExecuteSql", sql)
	defer defaultLog.Trace("ExecuteSql done")

	// Start a new transaction
	tx := pd.Db.Begin()

	// Ensure the transaction is rolled back in case of an error
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			secLog.Fatalf("Transaction failed: %v", r)
		}
	}()

	// Now we execute the raw SQL command within the transaction
	if err := tx.Exec(*sql).Error; err != nil {
		tx.Rollback()
		return errors.Wrap(err, "pgdb: failed to execute sql")
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		log.Fatalf("Failed to commit transaction: %v", err)
	}

	return nil
}

func (pd *PostgresDatabase) Migrate() error {
	defaultLog.Trace("Migrate")
	defer defaultLog.Trace("Migrate done")

	pd.Db.AutoMigrate(types.User{}, types.Role{}, types.Permission{})
	return nil
}

func (pd *PostgresDatabase) UserStore() domain.UserStore {
	return &PostgresUserStore{db: pd.Db}
}

func (pd *PostgresDatabase) RoleStore() domain.RoleStore {
	return &PostgresRoleStore{db: pd.Db}
}

func (pd *PostgresDatabase) PermissionStore() domain.PermissionStore {
	return &PostgresPermissionStore{db: pd.Db}
}

func (pd *PostgresDatabase) Close() {
	if pd.Db != nil {
		sqlDB, err := pd.Db.DB()
		if err != nil {
			defaultLog.WithError(err).Error("Error closing DB connection")
		}

		defaultLog.Info("Closing DB connection")
		sqlDB.Close()
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {
	defaultLog.Trace("Open DB")
	defer defaultLog.Trace("Open DB done")

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "require" {
		sslMode = "verify-full"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	dsn := fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		host, port, user, dbname, password, sslMode, sslCertParams)

	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 1

		db, dbErr = gorm.Open(postgres.Open(dsn), &gorm.Config{FullSaveAssociations: true,})
		if dbErr != nil {
			defaultLog.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i+1, numAttempts)
		} else {
			break
		}

		time.Sleep(retryTime * time.Second)
	}

	if dbErr != nil {
		defaultLog.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		secLog.Warningf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, errors.Wrapf(dbErr, "Failed to connect to db after %d attempts", numAttempts)
	}

	return &PostgresDatabase{Db: db}, nil
}
