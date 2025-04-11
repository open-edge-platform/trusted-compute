/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package authservice

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/version"
)

const helpStr = `Usage:
	authservice <command> [arguments]

Available Commands:
	-h|--help | help                 Show this help message
	setup <task>                     Run setup task
	start                            Start authservice
	status                           Show the status of authservice
	stop                             Stop authservice
	uninstall [--purge]              Uninstall authservice. --purge option needs to be applied to remove configuration and data files
	-v|--version | version           Show the version of authservice

Usage of authservice setup:
	authservice setup [task] [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

	Available Tasks for setup:
		all                      Runs all setup tasks
		download-ca-cert         Download CMS root CA certificate
		download-cert-tls        Download CA certificate from CMS for tls
		database                 Setup authservice database
		admin                    Add authservice admin username and password to database and assign respective 
		                         roles to the user
		jwt                      Create jwt signing key and jwt certificate signed by CMS
		create-credentials       Generates credentials to support third party authentication and authorization
		update-service-config    Sets or Updates the Service configuration 
`

func (a *App) printUsage() {
	fmt.Fprintln(a.consoleWriter(), helpStr)
}

func (a *App) printUsageWithError(err error) {
	fmt.Fprintln(a.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(a.errorWriter(), helpStr)
}

func (a *App) printVersion() {
	fmt.Fprintf(a.consoleWriter(), version.GetVersion())
}
