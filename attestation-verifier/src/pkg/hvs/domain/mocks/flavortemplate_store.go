/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockFlavorTemplateStore provides a mocked implementation of interface hvs.FlavorTemplate
type MockFlavorTemplateStore struct {
	FlavorTemplates  []hvs.FlavorTemplate
	DeletedTemplates []hvs.FlavorTemplate
}

var flavorTemplate = `{
	"id": "426912bd-39b0-4daa-ad21-0c6933230b50",
	"label": "default-uefi",
	"condition": [
		"//host_info/os_name='RedHatEnterprise'"
	],
	"flavor_parts": {
		"PLATFORM": {
			"meta": {
				"tpm_version": "2.0",
				"uefi_enabled": true,
				"vendor": "Linux"
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 0,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_equals": {}
				}
			]
		},
		"OS": {
			"meta": {
				"tpm_version": "2.0",
				"uefi_enabled": true,
				"vendor": "Linux"
			},
			"pcr_rules": [
				{
					"pcr": {
						"index": 7,
						"bank": "SHA256"
					},
					"pcr_matches": true,
					"eventlog_includes": [
						"shim",
						"db",
						"kek",
						"vmlinuz"
					]
				}
			]
		}
	}
}`

// Create and inserts a Flavortemplate
func (store *MockFlavorTemplateStore) Create(ft *hvs.FlavorTemplate) (*hvs.FlavorTemplate, error) {

	if ft.ID == uuid.Nil {
		ft.ID = uuid.New()
	}

	store.FlavorTemplates = append(store.FlavorTemplates, *ft)

	return ft, nil
}

// Retrieve a Flavortemplate
func (store *MockFlavorTemplateStore) Retrieve(templateID uuid.UUID, includeDeleted bool) (*hvs.FlavorTemplate, error) {

	for _, template := range store.FlavorTemplates {
		if template.ID == templateID {
			return &template, nil
		}
	}
	return nil, &commErr.StatusNotFoundError{Message: "FlavorTemplate with given ID is not found"}
}

// Search a Flavortemplate(s)
func (store *MockFlavorTemplateStore) Search(criteria *models.FlavorTemplateFilterCriteria) ([]hvs.FlavorTemplate, error) {
	rec := store.FlavorTemplates
	if criteria.IncludeDeleted {
		rec = append(rec, store.DeletedTemplates...)
	}

	var templates []hvs.FlavorTemplate
	for _, template := range rec {
		//ID
		if criteria.Ids != nil {
			for _, id := range criteria.Ids {
				if template.ID == id {
					templates = append(templates, template)
					break
				}
			}
		}

		//Label
		if criteria.Label != "" {
			if template.Label == criteria.Label {
				templates = append(templates, template)
			}
		}

		//Condition
		if criteria.ConditionContains != "" {
			for _, condition := range template.Condition {
				if condition == criteria.ConditionContains {
					templates = append(templates, template)
				}
			}
		}

		//FlavorPart
		if criteria.FlavorPartContains != "" {
			if template.FlavorParts.Platform != nil && criteria.FlavorPartContains == "PLATFORM" {
				templates = append(templates, template)
			}
			if template.FlavorParts.OS != nil && criteria.FlavorPartContains == "OS" {
				templates = append(templates, template)
			}
			if template.FlavorParts.HostUnique != nil && criteria.FlavorPartContains == "HOST_UNIQUE" {
				templates = append(templates, template)
			}
		}

		if criteria.Ids == nil && criteria.Label == "" && criteria.ConditionContains == "" && criteria.FlavorPartContains == "" {
			return rec, nil
		}
	}
	return templates, nil
}

// Detele a Flavortemplate
func (store *MockFlavorTemplateStore) Delete(templateID uuid.UUID) error {
	flavorTemplates := store.FlavorTemplates
	for i, template := range flavorTemplates {
		if template.ID == templateID {
			store.DeletedTemplates = append(store.DeletedTemplates, template)
			store.FlavorTemplates[i] = store.FlavorTemplates[len(store.FlavorTemplates)-1]
			store.FlavorTemplates = store.FlavorTemplates[:len(store.FlavorTemplates)-1]
			return nil
		}
	}
	return &commErr.StatusNotFoundError{Message: "FlavorTemplate with given ID is not found"}
}

// Recover a Flavortemplate
func (store *MockFlavorTemplateStore) Recover(labels []string) error {
	return nil
}

// NewFakeFlavorTemplateStore provides two dummy data for FlavorTemplates
func NewFakeFlavorTemplateStore() *MockFlavorTemplateStore {
	store := &MockFlavorTemplateStore{}

	var sf hvs.FlavorTemplate
	err := json.Unmarshal([]byte(flavorTemplate), &sf)
	fmt.Println("error: ", err)

	// add to store
	store.Create(&sf)

	return store
}

func (store *MockFlavorTemplateStore) AddFlavorgroups(uuid.UUID, []uuid.UUID) error {
	return nil
}
func (store *MockFlavorTemplateStore) RetrieveFlavorgroup(ftID uuid.UUID, fgID uuid.UUID) (*hvs.FlavorTemplateFlavorgroup, error) {
	if fgID == uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2") {
		return &hvs.FlavorTemplateFlavorgroup{}, nil
	} else if fgID == uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d") {
		return nil, errors.New("no rows in result set")
	} else if fgID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b53") {
		return nil, errors.New("Error in retrieving flavor")
	} else if fgID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b54") {
		return &hvs.FlavorTemplateFlavorgroup{}, nil
	}
	return nil, nil
}

func (store *MockFlavorTemplateStore) RemoveFlavorgroups(ftID uuid.UUID, fgId []uuid.UUID) error {
	if ftID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b51") {
		return nil
	} else if ftID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b54") {
		return errors.New("Error in deleting flavor group")
	}
	return nil
}

func (store *MockFlavorTemplateStore) SearchFlavorgroups(ftID uuid.UUID) ([]uuid.UUID, error) {
	if ftID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b51") {
		return []uuid.UUID{uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b51")}, nil
	} else if ftID == uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d") {
		return nil, errors.New("no rows in result set")
	} else if ftID == uuid.MustParse("426912bd-39b0-4daa-ad21-0c6933230b53") {
		return nil, errors.New("Error in retrieving flavor")
	}
	return nil, nil
}
