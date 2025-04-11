/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	clog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"time"
)

var log = clog.GetDefaultLogger()

const (
	ServiceUserName                = "cms"
	ServiceName                    = "CMS"
	ExplicitServiceName            = "Certificate Management Service"
	ApiVersion                     = "/v1"
	HomeDir                        = "/opt/cms/"
	ConfigDir                      = "/etc/cms/"
	ExecLinkPath                   = "/usr/bin/cms"
	RunDirPath                     = "/run/cms"
	LogDir                         = "/var/log/cms/"
	DefaultConfigFilePath          = ConfigDir + "config.yml"
	ConfigFile                     = "config"
	TokenKeyFile                   = "cms-jwt.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "jwt/"
	RootCADirPath                  = ConfigDir + "root-ca/"
	RootCACertPath                 = RootCADirPath + "root-ca-cert.pem"
	RootCAKeyPath                  = ConfigDir + "root-ca.key"
	RootCaCertFile                 = "root-ca-cert.pem"
	RootCaKeyFile                  = "root-ca.key"
	IntermediateCADirPath          = ConfigDir + "intermediate-ca/"
	TLSCertPath                    = ConfigDir + "tls-cert.pem"
	TLSKeyPath                     = ConfigDir + "tls.key"
	TLSCertFile                    = "tls-cert.pem"
	TLSKeyFile                     = "tls.key"
	SerialNumberPath               = ConfigDir + "serial-number"
	TlsCaCertFile                  = "tls-ca.pem"
	TlsCaKeyFile                   = "tls-ca.key"
	TlsClientCaCertFile            = "tls-client-ca.pem"
	TlsClientCaKeyFile             = "tls-client-ca.key"
	SigningCaCertFile              = "signing-ca.pem"
	SigningCaKeyFile               = "signing-ca.key"
	ServiceRemoveCmd               = "systemctl disable cms"
	DefaultRootCACommonName        = "CMSCA"
	DefaultTlsCACommonName         = "CMS TLS CA"
	DefaultTlsClientCaCommonName   = "CMS TLS Client CA"
	DefaultSigningCaCommonName     = "CMS Signing CA"
	DefaultPort                    = 8445
	DefaultOrganization            = "INTEL"
	DefaultCountry                 = "US"
	DefaultProvince                = "SF"
	DefaultLocality                = "SC"
	DefaultCACertValidity          = 5
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	CertApproverGroupName          = "CertApprover"
	DefaultAasJwtCn                = "AAS JWT Signing Certificate"
	DefaultAasTlsCn                = "AAS TLS Certificate"
	DefaultTlsSan                  = "127.0.0.1,localhost"
	DefaultTokenDurationMins       = 240
	DefaultJwtValidateCacheKeyMins = 60
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 10 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxlength       = 300
)

type CaAttrib struct {
	CommonName string
	CertPath   string
	KeyPath    string
}

const (
	Root      = "root"
	Tls       = "TLS"
	TlsClient = "TLS-Client"
	Signing   = "Signing"
)

var CertStoreMap = map[string]CaAttrib{
	Root:      {DefaultRootCACommonName, RootCACertPath, RootCAKeyPath},
	Tls:       {DefaultTlsCACommonName, IntermediateCADirPath + TlsCaCertFile, IntermediateCADirPath + TlsCaKeyFile},
	TlsClient: {DefaultTlsClientCaCommonName, IntermediateCADirPath + TlsClientCaCertFile, IntermediateCADirPath + TlsClientCaKeyFile},
	Signing:   {DefaultSigningCaCommonName, IntermediateCADirPath + SigningCaCertFile, IntermediateCADirPath + SigningCaKeyFile},
}

func GetIntermediateCAs() []string {
	log.Trace("constants/constants:GetIntermediateCAs() Entering")
	defer log.Trace("constants/constants:GetIntermediateCAs() Leaving")

	return []string{Tls, TlsClient, Signing}
}

func GetCaAttribs(t string, mpCaAtttibs map[string]CaAttrib) CaAttrib {
	log.Trace("constants/constants:GetCaAttribs() Entering")
	defer log.Trace("constants/constants:GetCaAttribs() Leaving")

	if val, found := mpCaAtttibs[t]; found {
		return val
	}
	return CaAttrib{}
}
