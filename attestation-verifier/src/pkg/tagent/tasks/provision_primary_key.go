/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

const provisionPrimaryKeyEnvHelpPrompt = "Following environment variables are required for " +
	constants.ProvisionPrimaryKeyCommand + " setup:"

var provisionPrimaryKeyEnvHelp = map[string]string{
	constants.EnvTPMOwnerSecret: "TPM Owner Secret",
}

type ProvisionPrimaryKey struct {
	TpmF           tpmprovider.TpmFactory
	OwnerSecretKey string
	envPrefix      string
	commandName    string
}

func (task *ProvisionPrimaryKey) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, provisionPrimaryKeyEnvHelpPrompt, "", provisionPrimaryKeyEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *ProvisionPrimaryKey) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

// This task is used to persist a primary public key at handle TPM_HANDLE_PRIMARY
// to be used by WLA for signing/binding keys.
func (task *ProvisionPrimaryKey) Run() error {
	log.Trace("tasks/provision_primary_key:Run() Entering")
	defer log.Trace("tasks/provision_primary_key:Run() Leaving")
	fmt.Println("Running setup task: provision-primary-key")

	tpmp, err := task.TpmF.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}
	defer tpmp.Close()

	exists, err := tpmp.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return errors.Wrap(err, "Error while checking existence of tpm public key")
	}

	if !exists {
		err = tpmp.CreatePrimaryHandle(task.OwnerSecretKey, tpmprovider.TPM_HANDLE_PRIMARY)
		if err != nil {
			return errors.Wrap(err, "Error while creating the primary handle in the TPM")
		}
	}

	return nil
}

func (task *ProvisionPrimaryKey) Validate() error {
	log.Trace("tasks/provision_primary_key:Validate() Entering")
	defer log.Trace("tasks/provision_primary_key:Validate() Leaving")

	var err error
	tpmp, err := task.TpmF.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}
	defer tpmp.Close()

	exists, err := tpmp.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		return errors.Wrap(err, "Error while checking existence of tpm public key")
	}

	if !exists {
		return errors.Errorf("The primary key at handle %x was not created", tpmprovider.TPM_HANDLE_PRIMARY)
	}

	// assume valid if error did not occur during 'Run'
	log.Debug("tasks/provision_primary_key:Validate() Provisioning the primary key was successful.")
	return nil
}
