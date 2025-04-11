/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"fmt"
	"io"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	log "github.com/sirupsen/logrus"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

type CreateDefaultFlavor struct {
	commConfig.DBConfig

	commandName      string
	flvGroupStorePtr domain.FlavorGroupStore
}

func (t *CreateDefaultFlavor) Run() error {
	fgStore, err := t.flvGroupStore()
	if err != nil {
		return err
	}

	for _, fg := range defaultFlavorGroups() {
		// check if the default flavorgroup is already created
		existingFG, err := fgStore.Search(&models.FlavorGroupFilterCriteria{
			NameEqualTo: fg.Name,
		})

		// create default flavorgroup ONLY if it does not exist already
		if len(existingFG) == 0 && err == nil {
			_, err := fgStore.Create(&fg)
			if err != nil {
				return errors.Wrap(err, "failed to create default flavor group \""+fg.Name+"\"")
			}
		}
	}
	return nil
}

func (t *CreateDefaultFlavor) Validate() error {
	fgStore, err := t.flvGroupStore()
	if err != nil {
		return err
	}
	for _, n := range defaultFlavorGroupsNames {
		searchFilter := models.FlavorGroupFilterCriteria{
			NameEqualTo: n,
		}
		fgList, err := fgStore.Search(&searchFilter)
		if err != nil {
			return errors.Wrap(err, "Failed to validate "+t.commandName)
		}
		if len(fgList) == 0 {
			return errors.New(t.commandName + ": default flavor \"" + n + "\" not created")
		}
	}
	return nil
}

func (t *CreateDefaultFlavor) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, "", DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *CreateDefaultFlavor) SetName(n, e string) {
	t.commandName = n
}

func (t *CreateDefaultFlavor) flvGroupStore() (domain.FlavorGroupStore, error) {
	if t.flvGroupStorePtr == nil {
		dataStore, err := postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &t.DBConfig))
		if err != nil {
			return nil, errors.Wrap(err, "failed to connect database")
		}
		t.flvGroupStorePtr = postgres.NewFlavorGroupStore(dataStore)
	}
	if t.flvGroupStorePtr == nil {
		return nil, errors.New("failed to create FlavorGroupStore")
	}
	return t.flvGroupStorePtr, nil
}

func defaultFlavorGroups() []hvs.FlavorGroup {
	var ret []hvs.FlavorGroup
	for _, fgStr := range defaultFlavorGroupsRaw {
		fg := hvs.FlavorGroup{}
		err := fg.UnmarshalJSON([]byte(fgStr))
		if err != nil {
			log.WithError(err).Errorf("Failed to unmarshal data")
		}
		ret = append(ret, fg)
	}
	return ret
}

var defaultFlavorGroupsNames = []string{
	"automatic",
	"platform_software",
	"workload_software",
	"host_unique",
}

var defaultFlavorGroupsRaw = []string{
	`{
		"name": "automatic",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "PLATFORM",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				},
				{
					"flavor_part": "OS",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				},
				{
					"flavor_part": "IMA",
					"match_policy": {
						"match_type": "ALL_OF",
						"required": "REQUIRED_IF_DEFINED"
					}
				},
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ALL_OF",
						"required": "REQUIRED_IF_DEFINED"
					}
				},
				{
					"flavor_part": "ASSET_TAG",
					"match_policy": {
						"match_type": "LATEST",
						"required": "REQUIRED_IF_DEFINED"
					}
				},
				{
					"flavor_part": "HOST_UNIQUE",
					"match_policy": {
						"match_type": "LATEST",
						"required": "REQUIRED_IF_DEFINED"
					}
				}
			]
		}
	}`,
	`{
		"name": "platform_software",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				}
			]
		}
	}`,
	`{
		"name": "workload_software",
		"flavor_match_policy_collection": {
			"flavor_match_policies": [
				{
					"flavor_part": "SOFTWARE",
					"match_policy": {
						"match_type": "ANY_OF",
						"required": "REQUIRED"
					}
				}
			]
		}
	}`,
	`{
		"name": "host_unique"
	}`,
}
