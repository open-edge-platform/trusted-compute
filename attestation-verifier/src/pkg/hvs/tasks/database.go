/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"io"
	"os"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"

	"github.com/pkg/errors"
)

type DBSetup struct {
	// embedded structure for holding new configuation
	commConfig.DBConfig
	SSLCertSource string

	// the pointer to configuration structure
	DBConfigPtr   *commConfig.DBConfig
	ConsoleWriter io.Writer

	envPrefix   string
	commandName string
}

// this is only used here, better don't put in constants package
const defaultSSLCertFilePath = constants.ConfigDir + "hvsdbsslcert.pem"

const DbEnvHelpPrompt = "Following environment variables are required for Database related setups:"

var DbEnvHelp = map[string]string{
	"DB_VENDOR":              "Vendor of database, or use HVS_DB_VENDOR alternatively",
	"DB_HOST":                "Database host name, or use HVS_DB_HOSTNAME alternatively",
	"DB_PORT":                "Database port, or use HVS_DB_PORT alternatively",
	"DB_NAME":                "Database name, or use HVS_DB_NAME alternatively",
	"DB_USERNAME":            "Database username, or use HVS_DB_USERNAME alternatively",
	"DB_PASSWORD":            "Database password, or use HVS_DB_PASSWORD alternatively",
	"DB_SSL_MODE":            "Database SSL mode, or use HVS_DB_SSL_MODE alternatively",
	"DB_SSL_CERT":            "Database SSL certificate, or use HVS_DB_SSLCERT alternatively",
	"DB_SSL_CERT_SOURCE":     "Database SSL certificate to be copied from, or use HVS_DB_SSLCERTSRC alternatively",
	"DB_CONN_RETRY_ATTEMPTS": "Database connection retry attempts",
	"DB_CONN_RETRY_TIME":     "Database connection retry time",
}

func (t *DBSetup) Run() error {
	if t.DBConfigPtr == nil {
		return errors.New("Pointer to database configuration structure can not be nil")
	}
	// validate input values
	if t.Vendor == "" {
		return errors.New("DB_VENDOR is not set, or use HVS_DB_VENDOR alternatively")
	}
	if t.Host == "" {
		return errors.New("DB_HOST is not set, or use HVS_DB_HOSTNAME alternatively")
	}
	if t.Port == 0 {
		return errors.New("DB_PORT is not set, or use HVS_DB_PORT alternatively")
	}
	if t.DBName == "" {
		return errors.New("DB_NAME is not set, or use HVS_DB_NAME alternatively")
	}
	if t.Username == "" {
		return errors.New("DB_USERNAME is not set, or use HVS_DB_USERNAME alternatively")
	}
	if t.Password == "" {
		return errors.New("DB_PASSWORD is not set, or use HVS_DB_PASSWORD alternatively")
	}
	if t.SSLMode == "" {
		t.SSLMode = constants.SslModeAllow
	}
	if t.ConnectionRetryAttempts < 0 {
		t.ConnectionRetryAttempts = constants.DefaultDbConnRetryAttempts
	}
	if t.ConnectionRetryTime < 0 {
		t.ConnectionRetryTime = constants.DefaultDbConnRetryTime
	}
	// set to default value
	if t.SSLCert == "" {
		t.SSLCert = defaultSSLCertFilePath
	}
	// populates the configuration structure
	t.DBConfigPtr.Vendor = t.Vendor
	t.DBConfigPtr.Host = t.Host
	t.DBConfigPtr.Port = t.Port
	t.DBConfigPtr.DBName = t.DBName
	t.DBConfigPtr.Username = t.Username
	t.DBConfigPtr.Password = t.Password

	t.DBConfigPtr.ConnectionRetryAttempts = t.ConnectionRetryAttempts
	t.DBConfigPtr.ConnectionRetryTime = t.ConnectionRetryTime

	var validErr error
	validErr = validation.ValidateHostname(t.DBConfig.Host)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db host")
	}
	validErr = validation.ValidateAccount(t.DBConfig.Username, t.DBConfig.Password)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db credentials")
	}
	validErr = validation.ValidateIdentifier(t.DBConfig.DBName)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on db name")
	}

	t.DBConfigPtr.SSLMode, t.DBConfigPtr.SSLCert, validErr = configureDBSSLParams(
		t.SSLMode, t.SSLCertSource, t.SSLCert)
	if validErr != nil {
		return errors.Wrap(validErr, "setup database: Validation failed on ssl settings")
	}
	// test connection and create schemas
	fmt.Fprintln(t.ConsoleWriter, "Connecting to DB and create schemas")
	dataStore, err := postgres.New(pgConfig(t.DBConfigPtr))
	if err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	dataStore.Migrate()
	return nil
}

func (t *DBSetup) Validate() error {
	if t.DBConfigPtr == nil {
		return errors.New("Pointer to database configuration structure can not be nil")
	}
	fmt.Fprintln(t.ConsoleWriter, "Validating DB args")
	// check everything set
	if t.DBConfigPtr.Vendor == "" ||
		t.DBConfigPtr.Host == "" ||
		t.DBConfigPtr.Port == 0 ||
		t.DBConfigPtr.DBName == "" ||
		t.DBConfigPtr.Username == "" ||
		t.DBConfigPtr.Password == "" ||
		t.DBConfigPtr.SSLMode == "" ||
		t.DBConfigPtr.SSLCert == "" {
		return errors.New("invalid database configuration")
	}
	// check if SSL certificate exists
	if t.DBConfigPtr.SSLMode == constants.SslModeVerifyCa ||
		t.DBConfigPtr.SSLMode == constants.SslModeVerifyFull {
		if _, err := os.Stat(t.SSLCert); os.IsNotExist(err) {
			return err
		}
	}
	// test connection
	if _, err := postgres.New(pgConfig(t.DBConfigPtr)); err != nil {
		return errors.Wrap(err, "Failed to connect database")
	}
	return nil
}

func (t *DBSetup) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, t.envPrefix, DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *DBSetup) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = setup.PrefixUnderscroll(e)
}

func configureDBSSLParams(sslMode, sslCertSrc, sslCert string) (string, string, error) {
	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	sslCert = strings.TrimSpace(sslCert)
	sslCertSrc = strings.TrimSpace(sslCertSrc)

	if sslMode != constants.SslModeAllow && sslMode != constants.SslModePrefer &&
		sslMode != constants.SslModeVerifyCa && sslMode != constants.SslModeRequire {
		sslMode = constants.SslModeVerifyFull
	}

	if sslMode == constants.SslModeVerifyCa || sslMode == constants.SslModeVerifyFull {
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
				return "", "", errors.Wrapf(err, "certificate source file not specified and sslcert %s does not exist", sslCertSrc)
			}
		}
		// at this point if sslCert destination is not passed it, lets set to default
		if sslCert == "" {
			sslCert = defaultSSLCertFilePath
		}
		// lets try to copy the file now. If copy does not succeed return the file copy error
		if err := cos.Copy(sslCertSrc, sslCert); err != nil {
			return "", "", errors.Wrap(err, "failed to copy file")
		}
		// set permissions so that non root users can read the copied file
		if err := os.Chmod(sslCert, 0644); err != nil {
			return "", "", errors.Wrapf(err, "could not apply permissions to %s", sslCert)
		}
	}
	return sslMode, sslCert, nil
}

func pgConfig(t *commConfig.DBConfig) *postgres.Config {
	return postgres.NewDatabaseConfig(t.Vendor, t)
}
