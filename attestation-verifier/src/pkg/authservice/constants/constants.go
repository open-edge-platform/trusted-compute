/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"crypto"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"time"
)

const (
	HomeDir         = "/opt/authservice/"
	ConfigDir       = "/etc/authservice/"
	ExecLinkPath    = "/usr/bin/authservice"
	RunDirPath      = "/run/authservice"
	NatsDirPath     = ConfigDir + "nats/"
	NatsNkeyDirPath = NatsDirPath + "nkeys/"

	LogDir = "/var/log/authservice/"

	DefaultConfigFilePath = ConfigDir + "config.yml"
	ConfigFile            = "config"

	TokenSignKeysAndCertDir = ConfigDir + "certs/tokensign/"
	TokenSignKeyFile        = TokenSignKeysAndCertDir + "jwt.key"
	TokenSignCertFile       = TokenSignKeysAndCertDir + "jwtsigncert.pem"

	OperatorSeedFile         = NatsNkeyDirPath + "operator-seed.txt"
	AccountSeedFile          = NatsNkeyDirPath + "account-seed.txt"
	AccountConfigurationFile = NatsDirPath + "server.conf"
	ComponentTypeHvs         = "HVS"
	ComponentTypeTa          = "TA"

	TrustedCAsStoreDir = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd   = "systemctl disable authservice"
	HashingAlgorithm   = crypto.SHA384

	ServiceCommand                 = "authservice"
	ServiceName                    = "AAS"
	ExplicitServiceName            = "Authentication and Authorization Service"
	ApiVersion                     = "v1"
	ServiceUserName                = "aas"
	DefaultPort                    = 8444
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyLength               = 3072
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasJwtDurationMins      = 120
	DefaultJwtValidateCacheKeyMins = 60
	DefaultLogEntryMaxLength       = 1500
	DefaultLogLevel                = "info"
)

const (
	DefaultDBVendor            = "postgres"
	DefaultDBName              = "aas_db"
	DefaultDbConnRetryAttempts = 4
	DefaultDbConnRetryTime     = 1
	DefaultSSLCertFilePath     = ConfigDir + "aasdbcert.pem"

	//Postgres connection SslModes
	SslModeAllow      = "allow"
	SslModePrefer     = "prefer"
	SslModeVerifyCa   = "verify-ca"
	SslModeRequire    = "require"
	SslModeVerifyFull = "verify-full"

	DBTypePostgres = "postgres"
)

const (
	DefaultAasTlsSan   = "127.0.0.1,localhost"
	DefaultAasTlsCn    = "AAS TLS Certificate"
	DefaultTLSCertFile = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile  = ConfigDir + "tls.key"
)

const (
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
)

const (
	DefaultReadTimeout       = 30 * time.Second
	DefaultReadHeaderTimeout = 10 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 10 * time.Second
	DefaultMaxHeaderBytes    = 1 << 20
)

//NATS Entity Types
const (
	Operator            = "operator"
	Account             = "account"
	User                = "user"
	DefaultOperatorName = "ISecL-operator"
	DefaultAccountName  = "ISecL-account"
	HvsUserName         = "ISecL-HVS"
)

var DefaultRoles = [5]string{Administrator, RoleManager, UserManager, UserRoleManager, CustomClaimsCreator}

const (
	Administrator       = "Administrator"
	RoleManager         = "RoleManager"
	UserManager         = "UserManager"
	UserRoleManager     = "UserRoleManager"
	CustomClaimsCreator = "CustomClaimsCreator"
)

func GetDefaultAdministratorRoles() []ct.RoleCreate {

	return []ct.RoleCreate{
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    Administrator,
				Context: "",
			},
			Permissions: []string{
				"*:*:*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    RoleManager,
				Context: "",
			},
			Permissions: []string{
				RoleCreate + ":*", RoleRetrieve + ":*", RoleSearch + ":*", RoleDelete + ":*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    UserManager,
				Context: "",
			},
			Permissions: []string{
				UserCreate + ":*", UserRetrieve + ":*", UserStore + ":*", UserSearch + ":*", UserDelete + ":*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    UserRoleManager,
				Context: "",
			},
			Permissions: []string{
				UserRoleCreate + ":*", UserRoleRetrieve + ":*", UserRoleSearch + ":*", UserRoleDelete + ":*",
			},
		},
		{
			RoleInfo: ct.RoleInfo{
				Service: ServiceName,
				Name:    CustomClaimsCreator,
				Context: "",
			},
			Permissions: []string{
				CustomClaimsCreate,
			},
		},
	}
}
