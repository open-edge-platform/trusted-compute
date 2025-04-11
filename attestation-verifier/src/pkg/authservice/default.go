/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package authservice

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/spf13/viper"
	"os"
	"time"
)

// this func sets the default values for viper keys
func init() {
	// set default values for tls
	viper.SetDefault(commConfig.TlsCertFile, constants.DefaultTLSCertFile)
	viper.SetDefault(commConfig.TlsKeyFile, constants.DefaultTLSKeyFile)
	viper.SetDefault(commConfig.TlsCommonName, constants.DefaultAasTlsCn)
	viper.SetDefault(commConfig.TlsSanList, constants.DefaultAasTlsSan)

	// set default values for log
	viper.SetDefault(commConfig.LogMaxLength, constants.DefaultLogEntryMaxLength)
	viper.SetDefault(commConfig.LogEnableStdout, true)
	viper.SetDefault(commConfig.LogLevel, constants.DefaultLogLevel)

	// set default values for server
	viper.SetDefault(commConfig.ServerPort, constants.DefaultPort)
	viper.SetDefault(commConfig.ServerReadTimeout, constants.DefaultReadTimeout)
	viper.SetDefault(commConfig.ServerReadHeaderTimeout, constants.DefaultReadHeaderTimeout)
	viper.SetDefault(commConfig.ServerWriteTimeout, constants.DefaultWriteTimeout)
	viper.SetDefault(commConfig.ServerIdleTimeout, constants.DefaultIdleTimeout)
	viper.SetDefault(commConfig.ServerMaxHeaderBytes, constants.DefaultMaxHeaderBytes)

	// set default for database config
	viper.SetDefault(commConfig.DbVendor, constants.DefaultDBVendor)
	viper.SetDefault(commConfig.DbHost, "localhost")
	viper.SetDefault(commConfig.DbPort, 5432)
	viper.SetDefault(commConfig.DbName, constants.DefaultDBName)
	viper.SetDefault(commConfig.DbSslMode, constants.SslModeVerifyFull)
	viper.SetDefault(commConfig.DbSslCert, constants.DefaultSSLCertFilePath)
	viper.SetDefault(commConfig.DbConnRetryAttempts, constants.DefaultDbConnRetryAttempts)
	viper.SetDefault(commConfig.DbConnRetryTime, constants.DefaultDbConnRetryTime)

	//set default for JWT and JWT signing cert
	viper.SetDefault(config.JwtIncludeKid, true)
	viper.SetDefault(config.JwtCertCommonName, constants.DefaultAasJwtCn)
	viper.SetDefault(config.JwtTokenDurationMins, constants.DefaultAasJwtDurationMins)

	viper.SetDefault(config.AuthDefenderMaxAttempts, constants.DefaultAuthDefendMaxAttempts)
	viper.SetDefault(config.AuthDefenderIntervalMins, constants.DefaultAuthDefendIntervalMins)
	viper.SetDefault(config.AuthDefenderLockoutDurationMins, constants.DefaultAuthDefendLockoutMins)

	viper.SetDefault(config.CreateCredentials, false)
	viper.SetDefault(config.NatsOperatorName, constants.DefaultOperatorName)
	viper.SetDefault(config.NatsAccountName, constants.DefaultAccountName)
	viper.SetDefault(config.NatsOperatorCredentialValidity, time.Hour*43800)
	viper.SetDefault(config.NatsAccountCredentialValidity, time.Hour*43800)
	viper.SetDefault(config.NatsUserCredentialValidity, time.Hour*8760)

}

func defaultConfig() *config.Configuration {
	// support old AAS env
	loadAlias()
	return &config.Configuration{
		CMSBaseURL:       viper.GetString(commConfig.CmsBaseUrl),
		CmsTlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),
		Log: commConfig.LogConfig{
			MaxLength:    viper.GetInt(commConfig.LogMaxLength),
			EnableStdout: viper.GetBool(commConfig.LogEnableStdout),
			Level:        viper.GetString(commConfig.LogLevel),
		},
		TLS: commConfig.TLSCertConfig{
			CertFile:   viper.GetString(commConfig.TlsCertFile),
			KeyFile:    viper.GetString(commConfig.TlsKeyFile),
			CommonName: viper.GetString(commConfig.TlsCommonName),
			SANList:    viper.GetString(commConfig.TlsSanList),
		},
	}
}

func loadAlias() {
	alias := map[string]string{
		commConfig.DbHost:                  "AAS_DB_HOSTNAME",
		commConfig.DbVendor:                "AAS_DB_VENDOR",
		commConfig.DbPort:                  "AAS_DB_PORT",
		commConfig.DbName:                  "AAS_DB_NAME",
		commConfig.DbUsername:              "AAS_DB_USERNAME",
		commConfig.DbPassword:              "AAS_DB_PASSWORD",
		commConfig.DbSslCert:               "AAS_DB_SSLCERT",
		commConfig.DbSslCertSource:         "AAS_DB_SSLCERTSRC",
		commConfig.DbSslMode:               "AAS_DB_SSL_MODE",
		commConfig.TlsCommonName:           "AAS_TLS_CERT_CN",
		commConfig.TlsSanList:              "SAN_LIST",
		commConfig.ServerReadTimeout:       "AAS_SERVER_READ_TIMEOUT",
		commConfig.ServerReadHeaderTimeout: "AAS_SERVER_READ_HEADER_TIMEOUT",
		commConfig.ServerWriteTimeout:      "AAS_SERVER_WRITE_TIMEOUT",
		commConfig.ServerIdleTimeout:       "AAS_SERVER_IDLE_TIMEOUT",
		commConfig.ServerMaxHeaderBytes:    "AAS_SERVER_MAX_HEADER_BYTES",
		config.AasServiceUsername:          "AAS_ADMIN_USERNAME",
		config.AasServicePassword:          "AAS_ADMIN_PASSWORD",
		config.JwtTokenDurationMins:        "AAS_JWT_TOKEN_DURATION_MINS",
		config.JwtIncludeKid:               "AAS_JWT_INCLUDE_KEYID",
		config.JwtCertCommonName:           "AAS_JWT_CERT_CN",
		commConfig.TlsCertFile:             "CERT_PATH",
		commConfig.TlsKeyFile:              "KEY_PATH",
	}
	for k, v := range alias {
		if env := os.Getenv(v); env != "" {
			viper.Set(k, env)
		}
	}
}
