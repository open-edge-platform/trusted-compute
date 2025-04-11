/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package bkc

import "fmt"

const helpStr = `Usage:
	bkc-tool <command>
`

func (app *App) printUsage() {
	fmt.Fprintln(app.consoleWriter(), helpStr)
}

func (app *App) printUsageWithError(err error) {
	fmt.Fprintln(app.errorWriter(), "Application returned with error:", err.Error())
	fmt.Fprintln(app.errorWriter(), helpStr)
}

func (app *App) printVersion() {
	fmt.Fprintln(app.consoleWriter(), "Best Known Compatibility (BKC) testing tool")
	fmt.Fprintln(app.consoleWriter(), "Version: "+app.Version)
	fmt.Fprintln(app.consoleWriter(), "Build: "+app.Build)
	fmt.Fprintln(app.consoleWriter(), "Build date: "+app.BuildDate)
}
