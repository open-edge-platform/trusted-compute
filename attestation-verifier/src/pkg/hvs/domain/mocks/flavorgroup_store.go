/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockFlavorgroupStore provides a mocked implementation of interface hvs.FlavorGroupStore

type MockFlavorgroupStore struct {
	FlavorgroupStore       map[uuid.UUID]*hvs.FlavorGroup
	HostFlavorgroupStore   []*hvs.HostFlavorgroup
	FlavorgroupFlavorStore map[uuid.UUID][]uuid.UUID
}

// Delete Flavorgroup
func (store *MockFlavorgroupStore) Delete(id uuid.UUID) error {

	if _, ok := store.FlavorgroupStore[id]; ok {
		delete(store.FlavorgroupStore, id)
		return nil
	}
	return errors.New(commErr.RowsNotFound)
}

// Hosts exist for Flavorgroup
func (store *MockFlavorgroupStore) HasAssociatedHosts(uuid.UUID) (bool, error) {
	return false, nil
}

// Retrieve returns FlavorGroup
func (store *MockFlavorgroupStore) Retrieve(id uuid.UUID) (*hvs.FlavorGroup, error) {
	if _, ok := store.FlavorgroupStore[id]; ok {
		return store.FlavorgroupStore[id], nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Search returns all FlavorGroups
func (store *MockFlavorgroupStore) Search(criteria *models.FlavorGroupFilterCriteria) ([]hvs.FlavorGroup, error) {

	var flvrGroups []hvs.FlavorGroup
	for _, fg := range store.FlavorgroupStore {
		flvrGroups = append(flvrGroups, *fg)
	}

	if criteria.Ids == nil && criteria.NameEqualTo == "" && criteria.NameContains == "" && (criteria.Limit == 1000 || criteria.Limit == 0) {
		return flvrGroups, nil
	} else if criteria.Limit == 2 || criteria.AfterId == 2 {
		return flvrGroups[:2], nil
	} else if len(criteria.Ids) > 0 {
		flavorgroups := []hvs.FlavorGroup{}
		for _, id := range criteria.Ids {
			fg, _ := store.Retrieve(id)
			flavorgroups = append(flavorgroups, *fg)
		}
		return flavorgroups, nil
	} else if criteria.NameEqualTo != "" {
		for _, fg := range store.FlavorgroupStore {
			if fg.Name == criteria.NameEqualTo {
				return []hvs.FlavorGroup{*fg}, nil
			}
		}
	} else if criteria.NameContains != "" {
		var flavorgroups []hvs.FlavorGroup
		for _, fg := range store.FlavorgroupStore {
			if strings.Contains(fg.Name, criteria.NameContains) {
				flavorgroups = append(flavorgroups, *fg)
			}
		}
		return flavorgroups, nil
	}
	return nil, nil
}

// Create inserts a Flavorgroup
func (store *MockFlavorgroupStore) Create(flavorgroup *hvs.FlavorGroup) (*hvs.FlavorGroup, error) {
	if flavorgroup.ID == uuid.Nil {
		newUuid, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "failed to create new UUID")
		}
		flavorgroup.ID = newUuid
	}
	store.FlavorgroupStore[flavorgroup.ID] = flavorgroup
	return flavorgroup, nil
}

func (store *MockFlavorgroupStore) AddFlavors(fgId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error) {
	// if fgID map does not exist add it
	if _, ok := store.FlavorgroupFlavorStore[fgId]; !ok {
		store.FlavorgroupFlavorStore[fgId] = fIds
	} else {
		for _, fid := range fIds {
			// add flavorid link
			store.FlavorgroupFlavorStore[fgId] = append(store.FlavorgroupFlavorStore[fgId], fid)
		}
	}
	return nil, nil
}

func (store *MockFlavorgroupStore) RemoveFlavors(fgId uuid.UUID, fIds []uuid.UUID) error {
	// if fgID map does not exist error out
	if _, ok := store.FlavorgroupFlavorStore[fgId]; !ok {
		return errors.New(commErr.RowsNotFound)
	}

	// let's check if all the flavors are present
	allFidsFound := true
	for _, fid := range fIds {
		foundFid := false
		for i, f := range store.FlavorgroupFlavorStore[fgId] {
			if f == fid {
				foundFid = true
				store.FlavorgroupFlavorStore[fgId] = append(store.FlavorgroupFlavorStore[fgId][:i], store.FlavorgroupFlavorStore[fgId][i+1:]...)
			}
		}
		if !foundFid {
			allFidsFound = false
			break
		}
	}

	if !allFidsFound {
		return errors.New(commErr.RowsNotFound)
	}
	return nil
}

func (store *MockFlavorgroupStore) SearchFlavors(fgId uuid.UUID) ([]uuid.UUID, error) {

	// if fgID map does not exist error out
	if _, ok := store.FlavorgroupFlavorStore[fgId]; !ok {
		return nil, errors.New(commErr.RowsNotFound)
	}

	if len(store.FlavorgroupFlavorStore[fgId]) == 0 {
		return nil, errors.New(commErr.RowsNotFound)
	}

	return store.FlavorgroupFlavorStore[fgId], nil
}

func (store *MockFlavorgroupStore) RetrieveFlavor(fgId uuid.UUID, fId uuid.UUID) (*hvs.FlavorgroupFlavorLink, error) {

	if fId == uuid.MustParse("5633146e-9a18-4f27-9db4-fcdf4d1f0e88") {
		return nil, errors.New("Error in retrieving flavor")
	}
	// if fgID map does not exist error out
	if _, ok := store.FlavorgroupFlavorStore[fgId]; !ok {
		return nil, errors.New(commErr.RowsNotFound)
	}

	for _, f := range store.FlavorgroupFlavorStore[fgId] {
		if f == fId {
			return &hvs.FlavorgroupFlavorLink{FlavorGroupID: fgId, FlavorID: fId}, nil
		}
	}

	return nil, errors.New(commErr.RowsNotFound)

}

// SearchHostsByFlavorGroup is used to fetch a list of hosts which are linked to the provided FlavorGroup
func (store *MockFlavorgroupStore) SearchFlavorTemplatesByFlavorGroup(fgID uuid.UUID) ([]uuid.UUID, error) {
	return nil, nil
}

func (store *MockFlavorgroupStore) SearchHostsByFlavorGroup(fgID uuid.UUID) ([]uuid.UUID, error) {
	var hIds []uuid.UUID
	for _, hf := range store.HostFlavorgroupStore {
		if hf.FlavorgroupId == fgID {
			hIds = append(hIds, hf.HostId)
		}
	}
	return hIds, nil
}

func (store *MockFlavorgroupStore) GetFlavorTypesInFlavorGroup(fgId uuid.UUID) (map[hvs.FlavorPartName]bool, error) {
	return make(map[hvs.FlavorPartName]bool), nil
}

func (store *MockFlavorgroupStore) AddFlavorTemplates(fgId uuid.UUID, ftIds []uuid.UUID) error {
	return nil
}

// NewFakeFlavorgroupStore provides two dummy data for Flavorgroups
func NewFakeFlavorgroupStore() *MockFlavorgroupStore {

	store := &MockFlavorgroupStore{
		FlavorgroupStore:       make(map[uuid.UUID]*hvs.FlavorGroup),
		FlavorgroupFlavorStore: make(map[uuid.UUID][]uuid.UUID),
	}

	_, err := store.Create(&hvs.FlavorGroup{
		RowId: 1,
		ID:    uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		Name:  "automatic",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: hvs.FlavorPartOs,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: hvs.FlavorPartPlatform,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: hvs.FlavorPartSoftware,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequiredIfDefined,
				},
			},
		},
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating Flavorgroup")
	}

	_, err = store.Create(&hvs.FlavorGroup{
		RowId: 2,
		ID:    uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e3"),
		Name:  "test",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: hvs.FlavorPartOs,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: hvs.FlavorPartPlatform,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAnyOf,
					Required:  hvs.FlavorRequired,
				},
			},
			{
				FlavorPart: hvs.FlavorPartSoftware,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequiredIfDefined,
				},
			},
		},
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating Flavorgroup")
	}
	_, err = store.Create(&hvs.FlavorGroup{
		RowId: 3,
		ID:    uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		Name:  "platform_software",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: hvs.FlavorPartSoftware,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequired,
				},
			},
		},
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating Flavorgroup")
	}

	if err != nil {
		defaultLog.WithError(err).Error("Error creating Flavorgroup")
	}
	_, err = store.Create(&hvs.FlavorGroup{
		RowId: 4,
		ID:    uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0e"),
		Name:  "workload_software",
		MatchPolicies: []hvs.FlavorMatchPolicy{
			{
				FlavorPart: hvs.FlavorPartSoftware,
				MatchPolicy: hvs.MatchPolicy{
					MatchType: hvs.MatchTypeAllOf,
					Required:  hvs.FlavorRequired,
				},
			},
		},
	})
	if err != nil {
		defaultLog.WithError(err).Error("Error creating Flavorgroup")
	}
	return store
}
