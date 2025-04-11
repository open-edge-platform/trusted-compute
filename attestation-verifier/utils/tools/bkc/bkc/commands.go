/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package bkc

import (
	"os"
	"path"

	commands "intel/isecl/tools/bkc/v5/bkc/internal"

	"github.com/pkg/errors"
)

var ErrTrustedBootNotValid = errors.New("invalid trusted boot configuration")

func (app *App) platformInfo(flag string) error {
	if flag == "--trusted-boot" {
		// this means using bkc tool binary to check what trust boot
		// configuration is used and if it is valid
		trustedBootOK, err := commands.CheckTrustedBoot(app.logWriter())
		if err != nil {
			return errors.Wrap(err, "failed to check trust boot configuration")
		}
		if trustedBootOK {
			return nil
		}
		// return an error if trust boot is not valid
		// this causes different return code in use for control flows in scripts
		return ErrTrustedBootNotValid
	}
	if err := commands.PlatFormInfoTest(app.logWriter()); err != nil {
		return errors.Wrap(err, "failed to execute platform-info tests")
	}
	return nil
}

func (app *App) tpmProvider() error {
	if err := commands.TPMProviderTest(app.logWriter(), app.TPMOwnerSecret, app.AIKSecret); err != nil {
		return errors.Wrap(err, "failed to execute tpm-provider tests")
	}
	return nil
}

func (app *App) attestation(flag string) error {
	commands.EventLogFile = app.EventLogFile
	commands.CACertFile = path.Join(app.RunDir, "ca.crt")
	commands.CACertKeyFile = path.Join(app.RunDir, "ca.key")
	commands.SavedFlavorFile = path.Join(app.RunDir, "flavor.json")
	commands.SavedManifestDir = path.Join(app.RunDir, "host-manifest")
	commands.SavedReportDir = path.Join(app.RunDir, "trust-report")
	commands.CheckNPWACMFile = path.Join(app.RunDir, "npw_acm")
	os.MkdirAll(commands.SavedManifestDir, 0777)
	os.MkdirAll(commands.SavedReportDir, 0777)
	if flag == "-c" {
		if err := commands.LoadAttestationFiles(); err != nil {
			return errors.Wrap(err, "failed to load saved attestation files")
		}
	}
	if errAttest := commands.Attestation(app.logWriter(), app.TPMOwnerSecret, app.AIKSecret, app.EventLogFile); errAttest != nil {
		return errors.Wrap(errAttest, "failed to execute attestation test")
	}
	return nil
}
