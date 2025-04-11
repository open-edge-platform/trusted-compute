/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/hostinfo"
	types "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

const downloadApiTokenEnvHelpPrompt = "Following environment variables are required for " +
	constants.DownloadApiTokenCommand + " setup:"

var downloadApiTokenEnvHelp = map[string]string{
	constants.EnvAASBaseURL:  "AAS API URL",
	constants.EnvBearerToken: "JWT token for authenticating with VS",
}

type DownloadApiToken struct {
	Config            *config.TrustAgentConfiguration
	AasClientProvider aas.AasClientProvider
	envPrefix         string
	commandName       string
}

func (task *DownloadApiToken) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, downloadApiTokenEnvHelpPrompt, "", downloadApiTokenEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *DownloadApiToken) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

//
// Downloads API Token from AAS
//
func (task *DownloadApiToken) Run() error {
	log.Trace("tasks/download_api_token:Run() Entering")
	defer log.Trace("tasks/download_api_token:Run() Leaving")

	var err error
	var hwuuid uuid.UUID
	fmt.Println("Running setup task: " + constants.DownloadApiTokenCommand)

	// validate hwuuid
	hInfo := hostinfo.NewHostInfoParser().Parse()
	if hInfo == nil {
		return errors.Errorf("Unable to obtain HostInfo for Host HWUUID")
	}
	if hwuuid, err = uuid.Parse(hInfo.HardwareUUID); err != nil || hwuuid == uuid.Nil {
		return errors.Errorf("Valid Host hardware UUID must be set to download API token from AAS")
	}

	permission := make(map[string]interface{})

	perms := []types.PermissionInfo{}
	perms = append(perms, types.PermissionInfo{
		Service: constants.VerificationServiceName,
		Rules:   []string{"reports:create:*", "hosts:search:*"},
	})
	permission["permissions"] = perms

	createCustomerClaimsReq := types.CustomClaims{
		Subject:      hwuuid.String(),
		ValiditySecs: constants.DefaultApiTokenExpiration,
		Claims:       permission,
	}

	// get the aas client from provider
	aasc, err := task.AasClientProvider.GetAasClient()
	if err != nil {
		return err
	}

	apiTokenBytes, err := aasc.GetCustomClaimsToken(createCustomerClaimsReq)
	if err != nil {
		return errors.Wrap(err, "Error while getting custom claims token")
	}

	task.Config.ApiToken = string(apiTokenBytes)

	return nil
}

// Validate Assume task is successful if API token is stored in config.yml already
func (task *DownloadApiToken) Validate() error {
	log.Trace("tasks/download_api_token:Validate() Entering")
	defer log.Trace("tasks/download_api_token:Validate() Leaving")

	if strings.TrimSpace(task.Config.ApiToken) == "" {
		return errors.Errorf("API token does not exist in TA config.yml")
	}

	log.Debug("tasks/download_api_token:Validate() download_api_token setup task was successful.")
	return nil
}
