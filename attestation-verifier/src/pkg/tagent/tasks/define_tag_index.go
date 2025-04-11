/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

const defineTagIndexEnvHelpPrompt = "Following environment variables are required for " +
	constants.DefineTagIndexCommand + " setup:"

var defineTagIndexEnvHelp = map[string]string{
	constants.EnvTPMOwnerSecret: "TPM Owner Secret",
}

type DefineTagIndex struct {
	TpmF           tpmprovider.TpmFactory
	OwnerSecretKey string
	Config         *config.TrustAgentConfiguration // out variable that is saved to AppConfig.TPM.tagSecretKey
	envPrefix      string
	commandName    string
}

func (task *DefineTagIndex) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, defineTagIndexEnvHelpPrompt, "", defineTagIndexEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *DefineTagIndex) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

func (task *DefineTagIndex) Run() error {

	// by default, define and store an empty 'tag' that is stored in nvram.
	newAssetTag := make([]byte, constants.TagIndexSize)

	fmt.Println("Running setup task: " + constants.DefineTagIndexCommand)

	tpmp, err := task.TpmF.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}
	defer tpmp.Close()

	owned, err := tpmp.IsOwnedWithAuth(task.OwnerSecretKey)
	if err != nil {
		return errors.Wrap(err, "Runtime error while verifying the owner-secret")
	}

	if !owned {
		return errors.New("The owner-secret provided cannot access the TPM.")
	}

	// if the tag-secret is not defined (i.e., not in config.yml), create a
	// new random key.
	if task.Config.Tpm.TagSecretKey == "" {
		tsk, err := crypt.GetHexRandomString(20)
		if err != nil {
			return errors.Wrap(err, "Error while generating a tag-secret")
		}

		task.Config.Tpm.TagSecretKey = fmt.Sprintf("%s%s", tpmprovider.HEX_PREFIX, tsk)
	}

	// check if an asset tag does not exist...
	nvExists, err := tpmp.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "Error checking if the tag index exists in nvram")
	}

	// If it exists, carry it forward so that trust-reports are still trusted...
	if nvExists {

		// read the existing asset tag
		existingAssetTag, err := tpmp.NvRead(task.OwnerSecretKey, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "Failed to read existing asset tag")
		}

		if existingAssetTag == nil || len(existingAssetTag) != constants.TagIndexSize {
			// we don't know what this is so just delete it.
			log.Warn("The existing asset tag is invalid will not be migrated")
		} else {
			log.Info("Migrating asset tag")
			copy(newAssetTag, existingAssetTag)
		}

		// delete old nvram index so that it can be recreated
		err = tpmp.NvRelease(task.OwnerSecretKey, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			return errors.Wrap(err, "Error deleting the previous tag index from nvram")
		}
	}

	// create an index for the tag
	err = tpmp.NvDefine(task.OwnerSecretKey, task.Config.Tpm.TagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, constants.TagIndexSize)
	if err != nil {
		return errors.Wrap(err, "Error defining the tag index in nvram")
	}

	// Either put back the existing asset tag or basically do a "memset" on the index
	// so that common.RequestHandler can determine if the tag is empty or defined.
	err = tpmp.NvWrite(task.Config.Tpm.TagSecretKey, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG, newAssetTag)
	if err != nil {
		return errors.Wrap(err, "Error writing tag to nvram")
	}

	return nil
}

func (task *DefineTagIndex) Validate() error {
	tpmp, err := task.TpmF.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "Error while creating NewTpmProvider")
	}
	defer tpmp.Close()

	// check if tagsecret is set
	if task.Config.Tpm.TagSecretKey == "" {
		return errors.New("TagSecretKey not populated")
	}

	// check if an asset tag does not exists...
	nvExists, err := tpmp.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		return errors.Wrap(err, "Validation error: NvIndexExists failed")
	}

	if !nvExists {
		return errors.New("The asset tag nvram index was not created")
	}

	log.Debugf("%s completed successfully", constants.DefineTagIndexCommand)
	return nil
}
