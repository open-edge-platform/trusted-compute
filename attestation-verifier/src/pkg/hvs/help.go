/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"fmt"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/version"
)

const helpStr = `Usage:
	hvs <command> [arguments]
	
Available Commands:
	help|-h|--help         Show this help message
	version|-v|--version   Show the version of current hvs build
	setup <task>           Run setup task
	start                  Start hvs
	status                 Show the status of hvs
	stop                   Stop hvs
	erase-data             Reset all tables in database and create default flavor groups
	config-db-rotation     Configure database table rotaition for audit log table, reference db_rotation.sql in documents
	uninstall [--purge]    Uninstall hvs
		--purge            all configuration and data files will be removed if this flag is set

Usage of hvs setup:
	hvs setup <task> [--help] [--force] [-f <answer-file>]
		--help                      show help message for setup task
		--force                     existing configuration will be overwritten if this flag is set
		-f|--file <answer-file>     the answer file with required arguments

Available Tasks for setup:
	all                             Runs all setup tasks
	database                        Setup hvs database
	create-default-flavorgroup      Create default flavor groups in database
	create-default-flavor-template  Create default flavor templates in database
	create-dek                      Create data encryption key for HVS
	download-ca-cert                Download CMS root CA certificate
	download-cert-tls               Download CA certificate from CMS for tls
	download-cert-saml              Download CA certificate from CMS for saml
	download-cert-flavor-signing    Download CA certificate from CMS for flavor signing
	create-endorsement-ca           Generate self-signed endorsement certificate
	create-privacy-ca               Generate self-signed privacy certificate
	create-tag-ca                   Generate self-signed tag certificate
	update-service-config           Sets or Updates the Service configuration  
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
