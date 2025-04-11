/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
)

type Database struct {
	commConfig.DBConfig
	DBConfigPtr *commConfig.DBConfig

	SSLCertSource string
	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

const DbEnvHelpPrompt = "Following environment variables are required for Database related setups:"

var DbEnvHelp = map[string]string{
	"DB_VENDOR":              "Vendor of database, or use AAS_DB_VENDOR alternatively",
	"DB_HOST":                "Database host name, or use AAS_DB_HOSTNAME alternatively",
	"DB_PORT":                "Database port, or use AAS_DB_PORT alternatively",
	"DB_NAME":                "Database name, or use AAS_DB_NAME alternatively",
	"DB_USERNAME":            "Database username, or use AAS_DB_USERNAME alternatively",
	"DB_PASSWORD":            "Database password, or use AAS_DB_PASSWORD alternatively",
	"DB_SSL_MODE":            "Database SSL mode, or use AAS_DB_SSL_MODE alternatively",
	"DB_SSL_CERT":            "Database SSL certificate, or use AAS_DB_SSLCERT alternatively",
	"DB_SSL_CERT_SOURCE":     "Database SSL certificate to be copied from, or use AAS_DB_SSLCERTSRC alternatively",
	"DB_CONN_RETRY_ATTEMPTS": "Database connection retry attempts",
	"DB_CONN_RETRY_TIME":     "Database connection retry time",
}

func (db *Database) Run() error {
	fmt.Fprintln(db.ConsoleWriter, "Running database setup...")

	// populates the configuration structure
	db.DBConfigPtr.Vendor = db.Vendor
	db.DBConfigPtr.Host = db.Host
	db.DBConfigPtr.Port = db.Port
	db.DBConfigPtr.DBName = db.DBName
	db.DBConfigPtr.Username = db.Username
	db.DBConfigPtr.Password = db.Password

	db.DBConfigPtr.ConnectionRetryAttempts = db.ConnectionRetryAttempts
	db.DBConfigPtr.ConnectionRetryTime = db.ConnectionRetryTime

	var validErr error

	validErr = validation.ValidateHostname(db.Host)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}
	validErr = validation.ValidateAccount(db.Username, db.Password)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}
	validErr = validation.ValidateIdentifier(db.DBName)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}

	db.DBConfigPtr.SSLMode, db.DBConfigPtr.SSLCert, validErr = configureDBSSLParams(
		db.SSLMode, db.SSLCertSource,
		db.SSLCert)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation fail")
	}

	fmt.Fprintln(db.ConsoleWriter, "Connecting to DB and create schemas", db.DBName)

	dataStore, err := postgres.New(pgConfig(db.DBConfigPtr))
	if err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	err = dataStore.Migrate()
	if err != nil {
		return errors.Wrap(err, "Failed to migrate database")
	}
	return nil
}

func configureDBSSLParams(sslMode, sslCertSrc, sslCert string) (string, string, error) {
	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	sslCert = strings.TrimSpace(sslCert)
	sslCertSrc = strings.TrimSpace(sslCertSrc)

	if sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "require" {
		sslMode = "verify-full"
	}

	if sslMode == "verify-ca" || sslMode == "verify-full" {
		// cover different scenarios
		if sslCertSrc == "" && sslCert != "" {
			if _, err := os.Stat(sslCert); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCert)
			}
			return sslMode, sslCert, nil
		}
		if sslCertSrc == "" {
			return "", "", errors.New("verify-ca or verify-full needs a source cert file to copy from unless db-sslcert exists")
		} else {
			if _, err := os.Stat(sslCertSrc); os.IsNotExist(err) {
				return "", "", errors.Wrapf(err, "Certificate source file not specified and sslcert %s does not exist", sslCertSrc)
			}
		}
		// at this point if sslCert destination is not passed it, lets set to default
		if sslCert == "" {
			sslCert = constants.DefaultSSLCertFilePath
		}
		// lets try to copy the file now. If copy does not succeed return the file copy error
		if err := cos.Copy(sslCertSrc, sslCert); err != nil {
			return "", "", errors.Wrap(err, "Failed to copy file")
		}
		// set permissions so that non root users can read the copied file
		if err := os.Chmod(sslCert, 0644); err != nil {
			return "", "", errors.Wrapf(err, "Could not apply permissions to %s", sslCert)
		}
	}
	return sslMode, sslCert, nil
}

func (db *Database) Validate() error {
	if db.DBConfigPtr.Host == "" {
		return errors.New("Hostname is not set")
	}
	if db.DBConfigPtr.Port == 0 {
		return errors.New("Port is not set")
	}
	if db.DBConfigPtr.Username == "" {
		return errors.New("Username is not set")
	}
	if db.DBConfigPtr.Password == "" {
		return errors.New("Password is not set")
	}
	if db.DBConfigPtr.DBName == "" {
		return errors.New("Schema is not set")
	}
	// check if SSL certificate exists
	if db.DBConfigPtr.SSLMode == constants.SslModeVerifyCa ||
		db.DBConfigPtr.SSLMode == constants.SslModeVerifyFull {
		if _, err := os.Stat(db.DBConfigPtr.SSLCert); os.IsNotExist(err) {
			return err
		}
	}
	_, err := postgres.Open(db.DBConfigPtr.Host, db.DBConfigPtr.Port, db.DBConfigPtr.DBName, db.DBConfigPtr.Username,
		db.DBConfigPtr.Password, db.DBConfigPtr.SSLMode, db.DBConfigPtr.SSLCert)
	if err != nil {
		return errors.Wrap(err, "setup database: Failed to open database")
	}
	// test connection
	if _, err := postgres.New(pgConfig(db.DBConfigPtr)); err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	return nil
}

func pgConfig(t *commConfig.DBConfig) *postgres.Config {
	return postgres.NewDatabaseConfig(t.Vendor, t)
}

func (db *Database) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, db.envPrefix, DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (db *Database) SetName(n, e string) {
	db.commandName = n
	db.envPrefix = setup.PrefixUnderscroll(e)
}
