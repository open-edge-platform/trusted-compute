/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package cms

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/cms/version"
)

const helpStr = `
Usage:
    cms <command> [arguments]

Available Commands:
    -h|--help | help               Show this help message
    setup [task]                   Run setup task
    start                          Start cms
    status                         Show the status of cms
    stop                           Stop cms
    tlscertsha384                  Show the SHA384 digest of the certificate used for TLS
    authtoken                      Show the JWT Token of cms
    uninstall [--purge]            Uninstall cms. --purge option needs to be applied to remove configuration and data files
    -v|--version | version         Show the version of cms

Usage of cms setup:
	cms setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
    all                       Runs all setup tasks
    root-ca                   Creates a self signed Root CA key pair in /etc/cms/root-ca/ for quality of life
    intermediate-ca           Creates a Root CA signed intermediate CA key pair(signing, tls-server and tls-client) in /etc/cms/intermediate-ca/ for quality of life
    tls                       Creates an intermediate-ca signed TLS key pair in /etc/cms for quality of life
    update-service-config     Sets or Updates the Service configuration 
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
