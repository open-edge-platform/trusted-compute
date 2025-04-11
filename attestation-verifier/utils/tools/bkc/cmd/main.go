/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"os"

	"intel/isecl/tools/bkc/v5/bkc"
)

const (
	runDir  = "/opt/bkc-tool/var"
	logFile = "/opt/bkc-tool/var/bkc.log"

	eventLog = "/opt/bkc-tool/var/measure-log.json"
)

var (
	Version   string
	Build     string
	BuildDate string
)

func main() {
	app := bkc.App{
		RunDir:       runDir,
		EventLogFile: eventLog,

		ConsoleWriter: os.Stdout,
		LogWriter:     os.Stdout,
		ErrorWriter:   os.Stderr,

		TPMOwnerSecret: "625d6d8a18f98bf794760fd392b8c01be0b4e959",
		AIKSecret:      "0d4ab6858cc8413a9a65a2b2de97a4693b1cf6a9",

		Version:   Version,
		Build:     Build,
		BuildDate: BuildDate,
	}
	if err := app.Run(os.Args); err != nil {
		if err == bkc.ErrTrustedBootNotValid {
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "error running tests: "+err.Error())
		os.Exit(1)
	}
}
