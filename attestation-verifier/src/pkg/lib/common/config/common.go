/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

// Constants for viper variable names. Will be used to set
// default values as well as to get each value
const (
	AasBaseUrl       = "aas-base-url"
	CmsBaseUrl       = "cms-base-url"
	BearerToken      = "bearer-token"
	CmsTlsCertSha384 = "cms-tls-cert-sha384"

	LogLevel        = "log.level"
	LogMaxLength    = "log.max-length"
	LogEnableStdout = "log.enable-stdout"

	TlsCertFile   = "tls.cert-file"
	TlsKeyFile    = "tls.key-file"
	TlsCommonName = "tls.common-name"
	TlsSanList    = "tls.san-list"

	ServerPort              = "server.port"
	ServerReadTimeout       = "server.read-timeout"
	ServerReadHeaderTimeout = "server.read-header-timeout"
	ServerWriteTimeout      = "server.write-timeout"
	ServerIdleTimeout       = "server.idle-timeout"
	ServerMaxHeaderBytes    = "server.max-header-bytes"
	SessionExpiryTime       = "session-expiry-time"

	DbVendor            = "db.vendor"
	DbHost              = "db.host"
	DbPort              = "db.port"
	DbName              = "db.name"
	DbUsername          = "db.username"
	DbPassword          = "db.password"
	DbSslMode           = "db.ssl-mode"
	DbSslCert           = "db.ssl-cert"
	DbSslCertSource     = "db.ssl-cert-source"
	DbConnRetryAttempts = "db.conn-retry-attempts"
	DbConnRetryTime     = "db.conn-retry-time"
)
