/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"fmt"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/version"
)

const helpStr = `Usage:

  tagent <command> [arguments]

Available Commands:

  help|-h|--help                   Show this help message.
  setup [all] [task]               Run setup task.
  uninstall                        Uninstall trust agent.
  --version                        Print build version info.
  start                            Start the trust agent service.
  stop                             Stop the trust agent service.
  status                           Get the status of the trust agent service.
  fetch-ekcert-with-issuer         Print Tpm Endorsement Certificate in Base64 encoded string along with issuer
                                   Optional environment variables:
                                   TPM_OWNER_SECRET=<40 byte hex>: When provided, command uses 40 character hex string as TPM owner secret.
                                                                     Else, uses empty string as owner secret.
  ima-load-policy                  Load Custom IMA policy to host kernel.

Setup command usage:  tagent setup [cmd] [-f <env-file>]

Available Tasks for 'setup', all commands support env file flag

  all                                       - Runs all setup tasks to provision the trust agent
  download-ca-cert                          - Downloads CMS root CA certificate
  download-cert                             - Downloads a signed TLS Certificate from CMS.
  download-credential                       - Fetches Credential from AAS
  download-api-token                        - Fetches Custom Claims Token from AAS
  update-certificates                       - Runs 'download-ca-cert' and 'download-cert'
  provision-attestation                     - Runs setup tasks associated with HVS/TPM provisioning
  create-host                               - Registers the trust agent with the verification service
  create-host-unique-flavor                 - Populates the verification service with the host unique flavor
  get-configured-manifest                   - Uses environment variables to pull application-integrity  
  update-service-config                     - Updates service configuration  
  define-tag-index                          - Allocates nvram in the TPM for use by asset tags.`

func (app *App) printUsage() {
	fmt.Fprintln(app.consoleWriter(), helpStr)
}

func (app *App) printUsageWithError(err error) {
	fmt.Fprintln(app.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(app.errorWriter(), helpStr)
}

func (app *App) printVersion() {
	fmt.Fprintf(app.consoleWriter(), version.GetVersion())
}
