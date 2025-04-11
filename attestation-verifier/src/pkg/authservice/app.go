/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package authservice

import (
	"flag"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	commLogInt "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
	"os"
	"os/exec"
	"runtime/debug"

	// Import driver for GORM
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var errInvalidCmd = errors.New("Invalid input after command")

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	Config *config.Configuration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
	LogWriter     io.Writer
	SecLogWriter  io.Writer
	HTTPLogWriter io.Writer
}

func (a *App) Run(args []string) error {
	defer func() {
		if err := recover(); err != nil {
			defaultLog.Errorf("Panic occurred: %+v", err)
			defaultLog.Error(string(debug.Stack()))
		}
	}()
	if len(args) < 2 {
		err := errors.New("Invalid usage of " + constants.ServiceCommand)
		a.printUsageWithError(err)
		return err
	}

	cmd := args[1]
	switch cmd {
	default:
		err := errors.New("Invalid command: " + cmd)
		a.printUsageWithError(err)
		return err
	case "run":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.startServer()
	case "help", "-h", "--help":
		a.printUsage()
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.status()
	case "uninstall":
		var purge bool
		flag.CommandLine.BoolVar(&purge, "purge", false, "purge config when uninstalling")
		err := flag.CommandLine.Parse(args[2:])
		if err != nil {
			return err
		}
		return a.uninstall(purge)
	case "version", "--version", "-v":
		a.printVersion()
		return nil
	case "setup":
		if err := a.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				a.printUsageWithError(err)
			} else {
				fmt.Fprintln(a.errorWriter(), err.Error())
			}
			return err
		}
	}
	return nil
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) errorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.Configuration {
	if a.Config != nil {
		return a.Config
	}
	c, err := config.LoadConfiguration()
	if err == nil {
		a.Config = c
		return a.Config
	}
	return nil
}

func (a *App) configureLogs(stdOut, logFile bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.logWriter()
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())

	logConfig := a.Config.Log
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(commLogMsg.LogInit)
	defaultLog.Info(commLogMsg.LogInit)
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "start", "authservice")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "stop", "authservice")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status authservice"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, "status", "authservice")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
