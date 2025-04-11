/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"fmt"
	commonExec "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/exec"
	"os"
	"os/exec"
	"syscall"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

func (a *App) executablePath() string {
	if a.ExecutablePath != "" {
		return a.ExecutablePath
	}
	exc, err := os.Executable()
	if err != nil {
		// if we can't find self-executable path, we're probably in a state that is panic() worthy
		panic(err)
	}
	return exc
}

func (a *App) homeDir() string {
	if a.HomeDir != "" {
		return a.HomeDir
	}
	return constants.InstallationDir
}

func (a *App) configDir() string {
	if a.ConfigDir != "" {
		return a.ConfigDir
	}
	return constants.ConfigDir
}

func (a *App) logDir() string {
	if a.LogDir != "" {
		return a.LogDir
	}
	return constants.LogDir
}

func (a *App) execLinkPath() string {
	if a.ExecLinkPath != "" {
		return a.ExecLinkPath
	}
	return constants.ExecLinkPath
}

// uninstall removes installation of trust agent
func (a *App) uninstall() error {
	// stop/disable tagent service (if installed and running)
	//
	// systemctl status tagent will...
	// return 4 if not present on the system
	// return 3 if stopped
	// return 0 if running
	//
	// If not present, do nothing
	// if stopped, remove
	// if running, stop and remove
	_, _, err := commonExec.RunCommandWithTimeout(constants.ServiceStatusCommand, 5)
	if err == nil {
		// installed and running, stop and disable
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceStopCommand, 5)
		_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
	} else {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 3 {
				// stopped, just disable
				_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableCommand, 5)
			} else if waitStatus.ExitStatus() == 4 {
				// do nothing if not installed
			} else {
				return errors.Errorf("main:uninstall() Service status returned unhandled error code %d", waitStatus.ExitStatus())
			}
		} else {
			return errors.Errorf("main:uninstall() An unhandled error occurred with the tagent service: %s", err)
		}
	}

	// always disable 'tagent_init.service' since it is not expected to be running (i.e. it's
	// a 'oneshot' service)
	_, _, _ = commonExec.RunCommandWithTimeout(constants.ServiceDisableInitCommand, 5)

	fmt.Println("TrustAgent service removed successfully")

	//
	// uninstall application agent (if uninstall script is present)
	//
	if _, err := os.Stat(constants.UninstallTbootXmScript); err == nil {
		_, _, err = commonExec.RunCommandWithTimeout(constants.UninstallTbootXmScript, 15)
		if err != nil {
			return errors.Errorf("main:uninstall() An error occurred while uninstalling application agent: %s", err)
		}
	}

	fmt.Println("Application-Agent removed successfully")

	//
	// remove all of tagent files (in /opt/trustagent/)
	//
	if _, err := os.Stat(constants.InstallationDir); err == nil {
		err = os.RemoveAll(constants.InstallationDir)
		if err != nil {
			log.WithError(err).Warnf("main:uninstall() An error occurred removing the trustagent files: %s", err)
		}
	}

	//
	// remove tagent symlink (in /usr/bin/tagent)
	//
	if _, err := os.Stat(constants.ExecLinkPath); err == nil {
		err = os.Remove(a.execLinkPath())
		if err != nil {
			log.WithError(err).Warnf("main:uninstall() An error occurred removing the trustagent symlink: %s", err)
		}
	}

	//
	// remove all of tagent files (in /var/log/trustagent)
	//
	if _, err := os.Stat(constants.LogDir); err == nil {
		err = os.RemoveAll(constants.LogDir)
		if err != nil {
			log.WithError(err).Warnf("main:uninstall() An error occurred removing the trustagent log files: %s", err)
		}
	}

	// remove all of tagent files (in /etc/trustagent)
	//
	if _, err := os.Stat(constants.ConfigDir); err == nil {
		err = os.RemoveAll(constants.ConfigDir)
		if err != nil {
			log.WithError(err).Warnf("main:uninstall() An error occurred removing the trustagent configuration files: %s", err)
		}
	}

	fmt.Println("TrustAgent files removed successfully")

	return nil
}

func (a *App) eraseData() error {
	if a.configuration() == nil {
		return errors.New("Failed to load configuration file")
	}
	return nil
}
