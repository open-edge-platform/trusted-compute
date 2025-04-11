/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package constants

//pem block/cert type
const (
	PemBlockTypeCert       = "CERTIFICATE"
	PemBlockTypePrivateKey = "PRIVATE KEY"
	PemBlockTypePublicKey  = "PUBLIC KEY"
	FlavorSigningCertType  = "flavor-signing"
	CertTypePolicySigning  = "policy-signing"
	CertTypeJwtSigning     = "JWT-Signing"
	CertTypeSigning        = "Signing"
	CertTypeTls            = "tls"
)

//setup task names
const (
	DownloadCaCert            = "download-ca-cert"
	DownloadCertPolicySigning = "download-cert-policy-signing"
	DownloadCertTls           = "download-cert-tls"
	DownloadCertJwtSigning    = "download-cert-jwt-signing"
	DownloadCertNonceSigning  = "download-cert-nonce-signing"
	Database                  = "database"
	UpdateServiceConfig       = "update-service-config"
)

//cli args
var (
	HelpArg    = [3]string{"help", "--help", "-h"}
	FileArg    = [2]string{"--file", "-f"}
	VersionArg = [3]string{"--version", "-v", "version"}
)

const (
	PurgeArg     = "--purge"
	ForceArg     = "--force"
	UninstallCmd = "uninstall"
	SetupCmd     = "setup"
	StartCmd     = "start"
	StopCmd      = "stop"
	StatusCmd    = "status"
	EraseDataCmd = "erase-data"
	RunCmd       = "run"
	SystemctlCmd = "systemctl"
	AllCmd       = "all"
)

//header constants
const (
	ContentTypeKey    = "Content-Type"
	AcceptKey         = "Accept"
	NonceKey          = "Nonce"
	AuthorizationKey  = "Authorization"
	BearerTokenPrefix = "Bearer "
)

const (
	Limit   = 1000
	AfterId = 0
)
