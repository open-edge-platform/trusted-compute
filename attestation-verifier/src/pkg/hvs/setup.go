/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"crypto/x509/pkix"
	"fmt"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/utils"
	"reflect"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/hrrs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/tasks"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	CertFile      = ".cert-file"
	KeyFile       = ".key-file"
	CommonName    = ".common-name"
	Issuer        = ".issuer"
	ValidityYears = ".validity-years"
	SanList       = ".san-list"
)

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		}
		if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err := setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}
	runner, err := a.setupTaskRunner()
	if err != nil {
		return err
	}
	cmd := args[1]
	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		}
		return nil
	}
	if cmd == "all" {
		if err = runner.RunAll(force); err != nil {
			errCmds := runner.FailedCommands()
			fmt.Fprintln(a.errorWriter(), "Error(s) encountered when running all setup commands:")
			for errCmd, failErr := range errCmds {
				fmt.Fprintln(a.errorWriter(), errCmd+": "+failErr.Error())
				err = runner.PrintHelp(errCmd)
				if err != nil {
					return errors.Wrap(err, "Failed to write to console")
				}
			}
			return errors.New("Failed to run all tasks")
		}
		fmt.Fprintln(a.consoleWriter(), "All setup tasks succeeded")
	} else {
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = a.Config.Save(constants.DefaultConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// Containers are always run as non root users, does not require changing ownership of config directories
	if utils.IsContainerEnv() {
		return nil
	}

	return cos.ChownDirForUser(constants.ServiceUserName, a.configDir())
}

// a helper function for setting up the task runner
func (a *App) setupTaskRunner() (*setup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	viper.AutomaticEnv()

	if a.configuration() == nil {
		a.Config = defaultConfig()
	}
	a.setupHRRSConfig()

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	dbConf := commConfig.DBConfig{
		Vendor:   viper.GetString(commConfig.DbVendor),
		Host:     viper.GetString(commConfig.DbHost),
		Port:     viper.GetInt(commConfig.DbPort),
		DBName:   viper.GetString(commConfig.DbName),
		Username: viper.GetString(commConfig.DbUsername),
		Password: viper.GetString(commConfig.DbPassword),
		SSLMode:  viper.GetString(commConfig.DbSslMode),
		SSLCert:  viper.GetString(commConfig.DbSslCert),

		ConnectionRetryAttempts: viper.GetInt(commConfig.DbConnRetryAttempts),
		ConnectionRetryTime:     viper.GetInt(commConfig.DbConnRetryTime),
	}

	runner.AddTask("database", "", &tasks.DBSetup{
		DBConfigPtr:   &a.Config.DB,
		DBConfig:      dbConf,
		SSLCertSource: viper.GetString(commConfig.DbSslCertSource),
		ConsoleWriter: a.consoleWriter(),
	})
	if reflect.DeepEqual(a.Config.DB, commConfig.DBConfig{}) {
		a.Config.DB = dbConf
	}
	runner.AddTask("create-default-flavorgroup", "", &tasks.CreateDefaultFlavor{
		DBConfig: a.Config.DB,
	})
	runner.AddTask("create-dek", "", &tasks.CreateDek{
		DekStore: &a.Config.Dek,
	})
	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedRootCACertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		TlsCertDigest: viper.GetString(commConfig.CmsTlsCertSha384),
	})
	runner.AddTask("download-cert-tls", "tls", &setup.DownloadCert{
		KeyFile:      viper.GetString(commConfig.TlsKeyFile),
		CertFile:     viper.GetString(commConfig.TlsCertFile),
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(commConfig.TlsCommonName),
		},
		SanList:       viper.GetString(commConfig.TlsSanList),
		CertType:      "tls",
		CaCertDirPath: constants.TrustedRootCACertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	})
	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ServiceConfig: commConfig.ServiceConfig{
			Username: viper.GetString(config.HvsServiceUsername),
			Password: viper.GetString(config.HvsServicePassword),
		},
		AASApiUrl: viper.GetString(commConfig.AasBaseUrl),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt(commConfig.ServerPort),
			ReadTimeout:       viper.GetDuration(commConfig.ServerReadTimeout),
			ReadHeaderTimeout: viper.GetDuration(commConfig.ServerReadHeaderTimeout),
			WriteTimeout:      viper.GetDuration(commConfig.ServerWriteTimeout),
			IdleTimeout:       viper.GetDuration(commConfig.ServerIdleTimeout),
			MaxHeaderBytes:    viper.GetInt(commConfig.ServerMaxHeaderBytes),
		},
		DefaultPort:   constants.DefaultHVSListenerPort,
		AppConfig:     &a.Config,
		NatServers:    viper.GetString(config.NatsServers),
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("download-cert-saml", "saml", a.downloadCertTask("saml"))
	runner.AddTask("download-cert-flavor-signing", "flavor-signing", a.downloadCertTask("flavor-signing"))

	runner.AddTask("create-privacy-ca", "privacy-ca", a.selfSignTask("privacy-ca"))
	runner.AddTask("create-endorsement-ca", "endorsement-ca", a.selfSignTask("endorsement-ca"))
	runner.AddTask("create-tag-ca", "tag-ca", a.selfSignTask("tag-ca"))
	runner.AddTask("create-default-flavor-template", "", &tasks.CreateDefaultFlavorTemplate{
		DBConf:    a.Config.DB,
		Directory: constants.DefaultFlavorTemplatesDirectory,
	})

	if strings.TrimSpace(viper.GetString(config.NatsServers)) != "" || len(a.Config.NATS.Servers) != 0 {
		runner.AddTask("download-credential", "", &setup.DownloadCredential{
			AasBaseUrL:         viper.GetString(commConfig.AasBaseUrl),
			BearerToken:        viper.GetString(commConfig.BearerToken),
			CaCertDirPath:      constants.TrustedRootCACertsDir,
			CredentialFilePath: constants.NatsCredentials,
			CreateCredentialReq: types.CreateCredentialsReq{
				ComponentType: constants.ServiceName,
			},
		})
	}
	return runner, nil
}

func (a *App) downloadCertTask(certType string) setup.Task {
	certTypeReq := certType
	var updateConfig *commConfig.SigningCertConfig
	var updateSAMLConfig *config.SAMLConfig
	var keyFile, certFile, commonName string
	switch certType {
	case "saml":
		updateConfig = &a.configuration().SAML.CommonConfig
		updateSAMLConfig = &a.configuration().SAML
		certTypeReq = "signing"
		keyFile = viper.GetString(certType + ".common" + KeyFile)
		certFile = viper.GetString(certType + ".common" + CertFile)
		commonName = viper.GetString(certType + ".common" + CommonName)
	case "flavor-signing":
		updateConfig = &a.configuration().FlavorSigning
		keyFile = viper.GetString(certType + KeyFile)
		certFile = viper.GetString(certType + CertFile)
		commonName = viper.GetString(certType + CommonName)
	}
	if updateConfig != nil {
		updateConfig.KeyFile = keyFile
		updateConfig.CertFile = certFile
		updateConfig.CommonName = commonName
	}
	if updateSAMLConfig != nil && updateConfig != nil {
		updateSAMLConfig.CommonConfig = *updateConfig
		updateSAMLConfig.ValiditySeconds = viper.GetInt(config.SamlValiditySeconds)
		updateSAMLConfig.Issuer = viper.GetString(config.SamlIssuer)
	}
	return &setup.DownloadCert{
		KeyFile:      keyFile,
		CertFile:     certFile,
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		CertType:      certTypeReq,
		CaCertDirPath: constants.TrustedRootCACertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	}
}

func (a *App) selfSignTask(name string) setup.Task {
	var updateConfig *commConfig.SelfSignedCertConfig
	switch name {
	case "privacy-ca":
		updateConfig = &a.configuration().PrivacyCA
	case "endorsement-ca":
		updateConfig = &a.configuration().EndorsementCA
	case "tag-ca":
		updateConfig = &a.configuration().TagCA
	}
	if updateConfig != nil {
		updateConfig.KeyFile = viper.GetString(name + KeyFile)
		updateConfig.CertFile = viper.GetString(name + CertFile)
		updateConfig.CommonName = viper.GetString(name + CommonName)
		updateConfig.Issuer = viper.GetString(name + Issuer)
		updateConfig.ValidityDays = viper.GetInt(name + ValidityYears)
	}
	return &setup.SelfSignedCert{
		CertFile:     viper.GetString(name + CertFile),
		KeyFile:      viper.GetString(name + KeyFile),
		CommonName:   viper.GetString(name + CommonName),
		Issuer:       viper.GetString(name + Issuer),
		SANList:      viper.GetString(name + SanList),
		ValidityDays: viper.GetInt(name + ValidityYears),

		ConsoleWriter: a.consoleWriter(),
	}
}

// The HRRS does not require setup, just one configuration parameter.  This function
// populates the HRRS config during 'hvs setup'.
//
// The function needs to handle...
// - The first run of setup with new a config.  The config will either have the default
//   values (from defaultConfig()) or custom values from env/answer file.
// - Setup is being re-run and the config has been previously populated (from 'new')...
//   - User has provided custom HRRS env/answer file values
//     ==> These should be applied to the config
//   - User has NOT provided custom HRRS env/answer file values
//     ==> Any previously configured custom values should be maintained
//
// This logic can achieved by just applying custom env/answer file values when they
// are different from the defaults.
func (a *App) setupHRRSConfig() {

	refreshPeriod := viper.GetDuration(constants.HrrsRefreshPeriod)
	if refreshPeriod != hrrs.DefaultRefreshPeriod {
		a.Config.HRRS.RefreshPeriod = refreshPeriod
	}
}
