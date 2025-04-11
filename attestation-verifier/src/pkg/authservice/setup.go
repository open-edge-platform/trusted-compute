/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package authservice

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/tasks"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
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
				defaultLog.WithError(err).Error("Failed to print help")
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				defaultLog.WithError(err).Error("Failed to print help")
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
					defaultLog.WithError(err).Error("Failed to print help")
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
				defaultLog.WithError(err).Error("Failed to print help")
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
	if err := a.configureLogs(false, true); err != nil {
		return nil, err
	}

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	runner.AddTask("download-ca-cert", "", &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCAsStoreDir,
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
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	})
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
	runner.AddTask("database", "", &tasks.Database{
		DBConfigPtr:   &a.Config.DB,
		DBConfig:      dbConf,
		SSLCertSource: viper.GetString(commConfig.DbSslCertSource),
		ConsoleWriter: a.consoleWriter(),
	})
	serviceConfig := config.AASConfig{
		Username: viper.GetString(config.AasServiceUsername),
		Password: viper.GetString(config.AasServicePassword),
	}
	runner.AddTask("admin", "", tasks.Admin{
		ServiceConfigPtr: &a.Config.AAS,
		AASConfig:        serviceConfig,
		DatabaseFactory: func() (domain.AASDatabase, error) {
			p, err := postgres.Open(a.Config.DB.Host, a.Config.DB.Port, a.Config.DB.DBName, a.Config.DB.Username,
				a.Config.DB.Password, a.Config.DB.SSLMode, a.Config.DB.SSLCert)
			if err != nil {
				defaultLog.WithError(err).Error("Failed to open postgres connection for setup task")
				return nil, err
			}
			err = p.Migrate()
			if err != nil {
				defaultLog.WithError(err).Error("Failed to migrate database")
			}
			return p, nil
		},
		ConsoleWriter: a.consoleWriter(),
	})
	runner.AddTask("jwt", "", &setup.DownloadCert{
		KeyFile:      constants.TokenSignKeyFile,
		CertFile:     constants.TokenSignCertFile,
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(config.JwtCertCommonName),
		},
		CertType:      "JWT-Signing",
		CaCertDirPath: constants.TrustedCAsStoreDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(commConfig.CmsBaseUrl),
		BearerToken:   viper.GetString(commConfig.BearerToken),
	})

	runner.AddTask("create-credentials", "", &tasks.CreateCredentials{
		CreateCredentials: viper.GetBool(config.CreateCredentials),
		NatsConfig: config.NatsConfig{
			Operator: config.NatsEntityInfo{
				Name:               viper.GetString(config.NatsOperatorName),
				CredentialValidity: viper.GetDuration(config.NatsOperatorCredentialValidity),
			},
			Account: config.NatsEntityInfo{
				Name:               viper.GetString(config.NatsAccountName),
				CredentialValidity: viper.GetDuration(config.NatsAccountCredentialValidity),
			},
		},
		ConsoleWriter:            a.consoleWriter(),
		OperatorSeedFile:         constants.OperatorSeedFile,
		AccountSeedFile:          constants.AccountSeedFile,
		AccountConfigurationFile: constants.AccountConfigurationFile,
	})

	runner.AddTask("update-service-config", "", &tasks.UpdateServiceConfig{
		ConsoleWriter: a.consoleWriter(),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt(commConfig.ServerPort),
			ReadTimeout:       viper.GetDuration(commConfig.ServerReadTimeout),
			ReadHeaderTimeout: viper.GetDuration(commConfig.ServerReadHeaderTimeout),
			WriteTimeout:      viper.GetDuration(commConfig.ServerWriteTimeout),
			IdleTimeout:       viper.GetDuration(commConfig.ServerIdleTimeout),
			MaxHeaderBytes:    viper.GetInt(commConfig.ServerMaxHeaderBytes),
		},
		DefaultPort: constants.DefaultPort,
		AppConfig:   &a.Config,
	})

	return runner, nil
}
