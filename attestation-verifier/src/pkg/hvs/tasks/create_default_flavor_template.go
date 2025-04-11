/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/google/uuid"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/pkg/errors"
)

type CreateDefaultFlavorTemplate struct {
	DBConf commConfig.DBConfig

	commandName   string
	TemplateStore domain.FlavorTemplateStore
	FGStore       domain.FlavorGroupStore
	Directory     string
}

var defaultFlavorTemplateNames = []string{
	"default-tc",
}

func (t *CreateDefaultFlavorTemplate) Run() error {

	if t.TemplateStore == nil {
		err := t.InitializeStores()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize flavor template store instance")
		}
	}

	templates, err := t.getTemplates()
	if err != nil {
		return err
	}

	defaultFlavorGroup, _ := t.FGStore.Search(&models.FlavorGroupFilterCriteria{
		NameEqualTo: models.FlavorGroupsAutomatic.String(),
	})
	defaultFlavorGroupId := defaultFlavorGroup[0].ID
	for _, ft := range templates {
		ftc := models.FlavorTemplateFilterCriteria{Label: ft.Label}
		ftList, err := t.TemplateStore.Search(&ftc)
		if err != nil {
			return errors.Wrap(err, "Failed to search the default flavor template(s)")
		}
		if len(ftList) == 0 {
			newTemplate, err := t.TemplateStore.Create(&ft)
			if err != nil {
				return errors.Wrap(err, "Failed to create default flavor template with ID \""+ft.ID.String()+"\"")
			}
			_, err = t.TemplateStore.RetrieveFlavorgroup(newTemplate.ID, defaultFlavorGroupId)
			if err != nil {
				if err := t.TemplateStore.AddFlavorgroups(newTemplate.ID, []uuid.UUID{defaultFlavorGroupId}); err != nil {
					return errors.Wrap(err, "Could not create flavortemplate-flavorgroup links")
				}
			}
		}
	}

	return nil
}

func (t *CreateDefaultFlavorTemplate) Validate() error {

	var ftList []hvs.FlavorTemplate
	defaultFlavorTemplateMap := map[string]bool{}
	deleted := []string{}
	var err error

	if t.TemplateStore == nil {
		err := t.InitializeStores()
		if err != nil {
			return errors.Wrap(err, "Failed to initialize flavor template store instance")
		}
	}

	for _, templateName := range defaultFlavorTemplateNames {
		defaultFlavorTemplateMap[templateName] = false
	}

	ftc := models.FlavorTemplateFilterCriteria{IncludeDeleted: false}
	ftList, err = t.TemplateStore.Search(&ftc)
	if err != nil {
		return errors.Wrap(err, "Failed to validate "+t.commandName)
	}
	if len(ftList) == 0 {
		return errors.New("No active templates found in db")
	}

	for _, template := range ftList {
		defaultFlavorTemplateMap[template.Label] = true
	}

	for _, templateName := range defaultFlavorTemplateNames {
		if !defaultFlavorTemplateMap[templateName] {
			deleted = append(deleted, templateName)
		}
	}

	if len(deleted) != 0 {
		return errors.New(t.commandName + ": Failed to recover deleted default flavor template(s) \"" + strings.Join(deleted, " "))
	}
	return nil
}

func (t *CreateDefaultFlavorTemplate) PrintHelp(w io.Writer) {
	setup.PrintEnvHelp(w, DbEnvHelpPrompt, "", DbEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *CreateDefaultFlavorTemplate) SetName(n, e string) {
	t.commandName = n
}

func (t *CreateDefaultFlavorTemplate) InitializeStores() error {
	var dataStore *postgres.DataStore
	var err error
	if t.TemplateStore == nil {
		dataStore, err = postgres.NewDataStore(postgres.NewDatabaseConfig(constants.DBTypePostgres, &t.DBConf))
		if err != nil {
			return errors.Wrap(err, "Failed to connect database")
		}
		t.TemplateStore = postgres.NewFlavorTemplateStore(dataStore)
		t.FGStore = postgres.NewFlavorGroupStore(dataStore)
	}

	return nil
}

func (t *CreateDefaultFlavorTemplate) getTemplates() ([]hvs.FlavorTemplate, error) {
	var ret []hvs.FlavorTemplate

	defaultFlavorTemplatesRaw, err := t.readDefaultTemplates()
	if err != nil {
		return nil, err
	}

	for _, ftStr := range defaultFlavorTemplatesRaw {
		var ft hvs.FlavorTemplate
		err := json.Unmarshal([]byte(ftStr), &ft)
		if err != nil {
			return nil, err
		}
		ret = append(ret, ft)
	}
	return ret, nil
}

// readDefaultTemplates This method is used to read the default template json files
func (t *CreateDefaultFlavorTemplate) readDefaultTemplates() ([]string, error) {
	var defaultFlavorTemplatesRaw []string

	flavorTemplatesPath, err := ioutil.ReadDir(t.Directory)
	if err != nil {
		return nil, err
	}

	for _, flavorTemplatePath := range flavorTemplatesPath {
		flavorTemplateBytes, err := ioutil.ReadFile(t.Directory + flavorTemplatePath.Name())
		if err != nil {
			return nil, err
		}
		defaultFlavorTemplatesRaw = append(defaultFlavorTemplatesRaw, string(flavorTemplateBytes))
	}
	return defaultFlavorTemplatesRaw, nil
}
