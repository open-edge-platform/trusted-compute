/*
* Copyright (C) 2025 Intel Corporation
* SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	flavorConsts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/pkg/errors"
)

const getConfiguredManifestEnvHelpPrompt = "Following environment variables are required for " +
	constants.GetConfiguredManifestCommand + " setup:"

var getConfiguredManifestEnvHelp = map[string]string{
	constants.EnvVSAPIURL:     "VS API URL",
	constants.EnvBearerToken:  "JWT token for authenticating with VS",
	constants.EnvFlavorUUIDs:  "CSV list of flavor UUIDs, At least of one of flavor UUIDs or flavor labels is required",
	constants.EnvFlavorLabels: "CSV list of flavor labels, At least of one of flavor UUIDs or flavor labels is required",
}

type GetConfiguredManifest struct {
	ClientFactory      hvsclient.HVSClientFactory
	savedManifestFiles []string // internal task variable that tracks saved manifests (used in Validate())
	envPrefix          string
	commandName        string
	VarDir             string
}

func (task *GetConfiguredManifest) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, getConfiguredManifestEnvHelpPrompt, "", getConfiguredManifestEnvHelp)
	fmt.Fprintln(w, "")
}

func (task *GetConfiguredManifest) SetName(n, e string) {
	task.commandName = n
	task.envPrefix = setup.PrefixUnderscroll(e)
}

func (task GetConfiguredManifest) saveManifest(manifestXml []byte) error {
	log.Trace("tasks/get-configured-manifest:saveManifest() Entering")
	defer log.Trace("tasks/get-configured-manifest:saveManifest() Leaving")

	manifest := hvsclient.Manifest{}
	err := xml.Unmarshal(manifestXml, &manifest)
	if err != nil {
		return errors.Wrap(err, "Error while unmarshalling the manifest xml")
	}

	if strings.Contains(manifest.Label, flavorConsts.DefaultSoftwareFlavorPrefix) ||
		strings.Contains(manifest.Label, flavorConsts.DefaultWorkloadFlavorPrefix) {
		log.Debugf("tasks/get-configured-manifest:saveManifest() Default flavor's manifest (%s) is part of installation, no need to deploy default flavor's manifest", manifest.Label)
		return nil
	}

	manifestFile := fmt.Sprintf("%s/manifest_%s.xml", task.VarDir, manifest.UUID)
	err = ioutil.WriteFile(manifestFile, manifestXml, 0600)
	if err != nil {
		return errors.Wrapf(err, "Error while writing %s/manifest_%s.xml file", task.VarDir, manifest.UUID)
	}

	// keep track of which manifests were saved, so they can be validated in 'Validate()'
	task.savedManifestFiles = append(task.savedManifestFiles, manifestFile)
	return nil
}

// Run uses "FLAVOR_UUIDS" and "FLAVOR_LABELS" environment variables to download
// application manifests from VS.
func (task *GetConfiguredManifest) Run() error {
	log.Trace("tasks/get-configured-manifest:Run() Entering")
	defer log.Trace("tasks/get-configured-manifest:Run() Leaving")
	fmt.Println("Running setup task: get-configured-manifest")

	var err error
	var flavorUUIDs []string
	var flavorLabels []string

	manifestsClient, err := task.ClientFactory.ManifestsClient()
	if err != nil {
		return errors.Wrap(err, "Could not create manifests client")
	}

	envVar := os.Getenv(constants.FlavorUUIDs)
	if envVar != "" {
		if len(envVar) > constants.FlavorUUIDMaxLength {
			secLog.Errorf("%s tasks/get-configured-manifest:Run() values given in %s exceeds maximum length limit", message.InvalidInputBadParam, constants.FlavorUUIDs)
			return errors.New("Flavor UUID exceeds maximum length limit")
		}
		tmp := strings.Split(envVar, ",")

		for _, uuid := range tmp {
			err = validation.ValidateUUIDv4(uuid)
			if err != nil {
				secLog.Errorf("%s tasks/get-configured-manifest:Run() Flavor UUID:'%s' is not a valid uuid", message.InvalidInputBadParam, uuid)
				return errors.Wrapf(err, "Flavor UUID:'%s' is not a valid uuid", uuid)
			}

			flavorUUIDs = append(flavorUUIDs, uuid)
		}
	}

	envVar = os.Getenv(constants.FlavorLabels)
	if len(envVar) > constants.FlavorLabelsMaxLength {
		secLog.Errorf("%s tasks/get-configured-manifest:Run() values given in %s exceeds maximum length limit", message.InvalidInputBadParam, constants.FlavorLabels)
		return errors.New("Flavor labels exceeds maximum length limit")
	}

	if envVar != "" {
		flavorLabels = strings.Split(envVar, ",")
	}

	err = validation.ValidateStrings(flavorLabels)
	if err != nil {
		secLog.Errorf("%s tasks/get-configured-manifest:Run() Flavor Labels:'%s' are not valid labels", message.InvalidInputBadParam, constants.FlavorLabels)
		return errors.Wrapf(err, "Flavor Labels:'%s' are not valid labels", constants.FlavorLabels)
	}

	if len(flavorUUIDs) == 0 && len(flavorLabels) == 0 {
		return errors.Errorf("No manifests were specified via the '%s' or '%s' environment variables", constants.FlavorUUIDs, constants.FlavorLabels)
	}

	for _, uuid := range flavorUUIDs {
		manifestXml, err := manifestsClient.GetManifestXmlById(uuid)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while downloading manifest with id '%s'", uuid)
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while saving manifest with id '%s'", uuid)
		}
	}

	for _, label := range flavorLabels {
		manifestXml, err := manifestsClient.GetManifestXmlByLabel(label)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while downloading manifest with label '%s'", label)
		}

		err = task.saveManifest(manifestXml)
		if err != nil {
			return errors.Wrapf(err, "An error occurred while saving manifest with label '%s'", label)
		}
	}

	return nil
}

func (task *GetConfiguredManifest) Validate() error {
	log.Trace("tasks/get-configured-manifest:Validate() Entering")
	defer log.Trace("tasks/get-configured-manifest:Validate() Leaving")
	missing := false

	for _, manifestFile := range task.savedManifestFiles {
		if _, err := os.Stat(manifestFile); os.IsNotExist(err) {
			log.Warnf("tasks/get-configured-manifest:Validate() Could not validate manifest '%s' was created", manifestFile)
			missing = true
		}
	}

	if missing {
		return errors.New("One or more manifest files were not created.")
	}

	log.Debug("tasks/get-configured-manifest:Validate() Get configured manifest was successful.")
	return nil
}
