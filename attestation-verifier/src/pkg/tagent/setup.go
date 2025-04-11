/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"crypto/x509/pkix"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/tasks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

var provisionAttestationTasks = []string{constants.DownloadPrivacyCACommand, constants.TakeOwnershipCommand, constants.DefineTagIndexCommand, constants.ProvisionAttestationIdentityKeyCommand, constants.ProvisionPrimaryKeyCommand}
var updateCertificatesTasks = []string{constants.DownloadRootCACertCommand, constants.DownloadCertCommand}

func runSetupTasksBatch(runner *setup.Runner, w io.Writer, isForced bool, cmds []string) error {
	for _, cmd := range cmds {
		if err := runner.Run(cmd, isForced); err != nil {
			fmt.Fprintln(w, cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}
	return nil
}

// input string slice should start with setup
func (a *App) setup(args []string) error {
	if len(args) < 2 {
		return errors.New("Invalid usage of setup")
	}
	// look for cli flags
	var ansFile string
	var force bool
	var err error
	for i, s := range args {
		if s == "-f" || s == "--file" {
			if i+1 < len(args) {
				ansFile = args[i+1]
			} else {
				return errors.New("Invalid answer file name")
			}
		} else if s == "--force" {
			force = true
		}
	}
	// dump answer file to env
	if ansFile != "" {
		err = setup.ReadAnswerFileToEnv(ansFile)
		if err != nil {
			return errors.Wrap(err, "Failed to read answer file")
		}
	}

	var runner *setup.Runner
	cmd := args[1]
	if len(args) > 2 && args[2] == "--help" {
		runner, err = a.setupTaskRunner("")
	} else {
		runner, err = a.setupTaskRunner(cmd)
	}

	if err != nil {
		return errors.Wrap(err, "Failed to run setup task runner")
	}

	// print help and return if applicable
	if len(args) > 2 && args[2] == "--help" {
		if cmd == "all" {
			err = runner.PrintAllHelp()
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		} else if cmd == constants.ProvisionAttestationCommand && args[2] == "--help" {
			for _, task := range provisionAttestationTasks {
				err = runner.PrintHelp(task)
				if err != nil {
					return errors.Wrap(err, "Failed to write to console")
				}
			}
		} else if cmd == constants.UpdateCertificatesCommand && args[2] == "--help" {
			for _, task := range updateCertificatesTasks {
				err = runner.PrintHelp(task)
				if err != nil {
					return errors.Wrap(err, "Failed to write to console")
				}
			}
		} else {
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
		}
		return nil
	}

	// define groups of tasks in the next section
	// individual tasks can be cherry-picked by setup.Run(taskName)
	taskSet := []string{}
	switch cmd {
	case constants.DefaultSetupCommand:
		taskSet = []string{
			constants.UpdateServiceConfigCommand,
			constants.DownloadRootCACertCommand,
			constants.DownloadPrivacyCACommand,
			constants.TakeOwnershipCommand,
			constants.DefineTagIndexCommand,
			constants.ProvisionAttestationIdentityKeyCommand,
			constants.ProvisionPrimaryKeyCommand,
			constants.DownloadApiTokenCommand,
		}

		if a.config.Mode == constants.CommunicationModeOutbound {
			taskSet = append(taskSet, constants.DownloadCredentialCommand)
		} else {
			taskSet = append(taskSet, constants.DownloadCertCommand)
		}

	case constants.ProvisionAttestationCommand:
		taskSet = provisionAttestationTasks

	case constants.UpdateCertificatesCommand:
		taskSet = updateCertificatesTasks

	case constants.DownloadCredentialCommand:
		if a.config.Mode == constants.CommunicationModeOutbound {
			taskSet = []string{
				constants.DownloadCredentialCommand,
			}
		} else {
			return errors.Errorf("cannot run download-credential task when %s is not set to %s",
				constants.EnvTAServiceMode, constants.CommunicationModeOutbound)
		}

	default:
		if err = runner.Run(cmd, force); err != nil {
			fmt.Fprintln(a.errorWriter(), cmd+": "+err.Error())
			err = runner.PrintHelp(cmd)
			if err != nil {
				return errors.Wrap(err, "Failed to write to console")
			}
			return errors.New("Failed to run setup task " + cmd)
		}
	}

	err = runSetupTasksBatch(runner, a.errorWriter(), force, taskSet)
	if err != nil {
		return err
	}

	err = a.config.SaveConfiguration(constants.ConfigFilePath)
	if err != nil {
		return errors.Wrap(err, "Failed to save configuration")
	}
	// Containers are always run as non-root users, does not require changing ownership of config directories
	if utils.IsContainerEnv() {
		return nil
	}

	return cos.ChownDirForUser(constants.TagentUserName, a.configDir())
}

// input string slice should start with setup
func (a *App) setupTaskRunner(cmd string) (*setup.Runner, error) {

	loadAlias()
	viper.SetEnvKeyReplacer(strings.NewReplacer(
		constants.ViperKeyDashSeparator, constants.EnvNameSeparator,
		constants.ViperDotSeparator, constants.EnvNameSeparator))
	viper.AutomaticEnv()

	if a.configuration() == nil {
		a.config = defaultConfig()
	}

	runner := setup.NewRunner()
	runner.ConsoleWriter = a.consoleWriter()
	runner.ErrorWriter = a.errorWriter()

	// initialize tasks
	downloadCaCertTask := &setup.DownloadCMSCert{
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(constants.CmsBaseUrlViperKey),
		TlsCertDigest: viper.GetString(constants.CmsTlsCertSha384ViperKey),
	}

	downloadCertTlsTask := &setup.DownloadCert{
		KeyFile:      constants.TLSKeyFilePath,
		CertFile:     constants.TLSCertFilePath,
		KeyAlgorithm: constants.DefaultKeyAlgorithm,
		KeyLength:    constants.DefaultKeyAlgorithmLength,
		Subject: pkix.Name{
			CommonName: viper.GetString(constants.TlsCommonNameViperKey),
		},
		SanList:       viper.GetString(constants.TlsSanListViperKey),
		CertType:      constants.TlsKey,
		CaCertDirPath: constants.TrustedCaCertsDir,
		ConsoleWriter: a.consoleWriter(),
		CmsBaseURL:    viper.GetString(constants.CmsBaseUrlViperKey),
		BearerToken:   viper.GetString(constants.BearerTokenViperKey),
	}

	updateServiceConfigTask := &tasks.UpdateServiceConfig{
		AASApiUrl: viper.GetString(constants.AasBaseUrlViperKey),
		ServerConfig: commConfig.ServerConfig{
			Port:              viper.GetInt(constants.ServerPortViperKey),
			ReadTimeout:       viper.GetDuration(constants.ServerReadTimeoutViperKey),
			ReadHeaderTimeout: viper.GetDuration(constants.ServerReadHeaderTimeoutViperKey),
			WriteTimeout:      viper.GetDuration(constants.ServerWriteTimeoutViperKey),
			IdleTimeout:       viper.GetDuration(constants.ServerIdleTimeoutViperKey),
			MaxHeaderBytes:    viper.GetInt(constants.ServerMaxHeaderBytesViperKey),
		},
		LoggingConfig: commConfig.LogConfig{
			MaxLength:    viper.GetInt(constants.LogEntryMaxLengthViperKey),
			EnableStdout: viper.GetBool(constants.LogEnableStdoutViperKey),
			Level:        viper.GetString(constants.TaLogLevelViperKey),
		},
		NatServers: config.NatsService{
			Servers: strings.Split(viper.GetString(constants.NatsServersViperKey), constants.DefaultTaTlsSanSeparator),
			HostID:  viper.GetString(constants.NatsTaHostIdViperKey),
		},
		AppConfig: a.config,
	}

	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		return nil, err
	}

	// TODO: Move this code to corresponding set up task
	// singular HVS client for all tasks that need one
	var hvsClientFactory hvsclient.HVSClientFactory
	switch cmd {
	case constants.DefaultSetupCommand,
		constants.DownloadPrivacyCACommand,
		constants.CreateHostUniqueFlavorCommand,
		constants.CreateHostCommand,
		constants.GetConfiguredManifestCommand,
		constants.ProvisionAttestationCommand:

		// validate the HVS url
		hvsUrl := viper.GetString(constants.HvsUrlViperKey)
		if _, err := url.ParseRequestURI(hvsUrl); err != nil {
			return nil, errors.Wrapf(err, "Invalid %s", constants.EnvVSAPIURL)
		}

		// validate the bearer token
		bearerToken := util.GetBearerToken()
		if bearerToken == "" {
			return nil, errors.Errorf("%s is not set", constants.EnvBearerToken)
		}
		// Initialize the HostsClient using the factory
		hvsClientFactory, err = hvsclient.NewVSClientFactory(hvsUrl, bearerToken, constants.TrustedCaCertsDir)
		if err != nil {
			return nil, errors.Wrap(err, "Could not create the hvsclient factory")
		}
	}

	// singular AAS client factory for all tasks that need one
	var aasCP aas.AasClientProvider
	switch cmd {
	case constants.DefaultSetupCommand,
		constants.DownloadCredentialCommand,
		constants.DownloadApiTokenCommand:
		aasUrl := viper.GetString(constants.AasBaseUrlViperKey)

		if _, err := url.ParseRequestURI(aasUrl); err != nil {
			return nil, errors.Wrapf(err, "Invalid %s", constants.EnvAASBaseURL)
		}

		// validate the bearer token
		bearerToken := util.GetBearerToken()
		if bearerToken == "" {
			return nil, errors.Errorf("%s is not set", constants.EnvBearerToken)
		}

		if !strings.HasSuffix(aasUrl, "/") {
			aasUrl += "/"
		}

		aasCP = aas.DefaultAasClientProvider{
			AasUrl:      aasUrl,
			BearerToken: bearerToken,
			CaCertsDir:  constants.TrustedCaCertsDir,
		}
	}

	downloadPrivacyCaTask := &tasks.DownloadPrivacyCA{
		ClientFactory: hvsClientFactory,
		PrivacyCA:     constants.PrivacyCA,
	}

	provisionAttIdKeyTask := &tasks.ProvisionAttestationIdentityKey{
		TpmF:                 tpmFactory,
		ClientFactory:        hvsClientFactory,
		OwnerSecretKey:       viper.GetString(constants.TpmOwnerSecretViperKey),
		EndorsementSecretKey: viper.GetString(constants.TpmEndorsementSecretViperKey),
		PrivacyCA:            constants.PrivacyCA,
		AikCert:              constants.AikCert,
	}

	createHostCommandTask := &tasks.CreateHost{
		AppConfig:      a.config,
		ClientFactory:  hvsClientFactory,
		TrustAgentPort: viper.GetInt(constants.ServerPortViperKey),
	}

	createHostUniqueFlavorTask := &tasks.CreateHostUniqueFlavor{
		AppConfig:      a.config,
		ClientFactory:  hvsClientFactory,
		TrustAgentPort: viper.GetInt(constants.ServerPortViperKey),
	}

	getConfiguredManifestTask := &tasks.GetConfiguredManifest{
		ClientFactory: hvsClientFactory,
		VarDir:        constants.VarDir,
	}

	takeOwnershipTask := &tasks.TakeOwnership{
		TpmF:                 tpmFactory,
		OwnerSecretKey:       viper.GetString(constants.TpmOwnerSecretViperKey),
		EndorsementSecretKey: viper.GetString(constants.TpmEndorsementSecretViperKey),
	}

	provisionPrimaryKeyTask := &tasks.ProvisionPrimaryKey{
		TpmF:           tpmFactory,
		OwnerSecretKey: viper.GetString(constants.TpmOwnerSecretViperKey),
	}

	defineTagIndexTask := &tasks.DefineTagIndex{
		TpmF:           tpmFactory,
		Config:         a.config,
		OwnerSecretKey: viper.GetString(constants.TpmOwnerSecretViperKey),
	}

	downloadCredentialTask := &tasks.DownloadCredential{
		AasClientProvider: aasCP,
		HostId:            viper.GetString(constants.NatsTaHostIdViperKey),
		NatsCredentials:   constants.NatsCredentials,
	}

	downloadApiToken := &tasks.DownloadApiToken{
		Config:            a.config,
		AasClientProvider: aasCP,
	}

	// required tasks in correct order
	runner.AddTask(constants.UpdateServiceConfigCommand, "", updateServiceConfigTask)
	runner.AddTask(constants.DownloadRootCACertCommand, "", downloadCaCertTask)
	runner.AddTask(constants.DownloadPrivacyCACommand, "", downloadPrivacyCaTask)
	runner.AddTask(constants.TakeOwnershipCommand, "", takeOwnershipTask)
	runner.AddTask(constants.DefineTagIndexCommand, "", defineTagIndexTask)
	runner.AddTask(constants.ProvisionAttestationIdentityKeyCommand, "", provisionAttIdKeyTask)
	runner.AddTask(constants.ProvisionPrimaryKeyCommand, "", provisionPrimaryKeyTask)
	runner.AddTask(constants.DownloadApiTokenCommand, "", downloadApiToken)
	// choose next task based on NATS/HTTPS communication mode by caller
	runner.AddTask(constants.DownloadCredentialCommand, "", downloadCredentialTask)
	runner.AddTask(constants.DownloadCertCommand, constants.TlsKey, downloadCertTlsTask)

	// optional tasks
	runner.AddTask(constants.CreateHostCommand, "", createHostCommandTask)
	runner.AddTask(constants.CreateHostUniqueFlavorCommand, "", createHostUniqueFlavorTask)
	runner.AddTask(constants.GetConfiguredManifestCommand, "", getConfiguredManifestTask)

	return runner, nil
}
