/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package bkc

import (
	"errors"
	"io"
	"os"
)

const defaultSecret = "0000000000000000000000000000000000000000"

type App struct {
	RunDir string

	TPMOwnerSecret string
	AIKSecret      string

	EventLogFile string

	ConsoleWriter io.Writer
	LogWriter     io.Writer
	ErrorWriter   io.Writer

	Version   string
	Build     string
	BuildDate string
}

func (app *App) Run(args []string) error {
	if len(args) < 2 {
		err := errors.New("Invalid usage of BKC tool binary")
		app.printUsageWithError(err)
		return err
	}
	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		app.printUsageWithError(err)
		return err
	case "version":
		app.printVersion()
		return nil
	case "platform-info":
		if len(args) != 2 && len(args) != 3 {
			err := errors.New("Invalid usage of BKC tool binary command: platform-info")
			app.printUsageWithError(err)
			return err
		}
		if len(args) == 3 {
			return app.platformInfo(args[2])
		}
		return app.platformInfo("")
	case "tpm-provider":
		if len(args) != 2 {
			err := errors.New("Invalid usage of BKC tool binary command: tpm-provider")
			app.printUsageWithError(err)
			return err
		}
		if app.TPMOwnerSecret == "" {
			app.TPMOwnerSecret = defaultSecret
		}
		if app.AIKSecret == "" {
			app.AIKSecret = defaultSecret
		}
		return app.tpmProvider()
	case "attestation":
		if len(args) != 2 && len(args) != 3 {
			err := errors.New("Invalid usage of BKC tool binary command: attestation")
			app.printUsageWithError(err)
			return err
		}
		if len(args) == 3 {
			return app.attestation(args[2])
		}
		return app.attestation("")
	}
}

func (app *App) consoleWriter() io.Writer {
	if app.ConsoleWriter != nil {
		return app.ConsoleWriter
	}
	return os.Stdout
}

func (app *App) errorWriter() io.Writer {
	if app.ErrorWriter != nil {
		return app.ErrorWriter
	}
	return os.Stderr
}

func (app *App) logWriter() io.Writer {
	if app.LogWriter != nil {
		return app.LogWriter
	}
	return os.Stderr
}
