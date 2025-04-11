/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"reflect"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockHostStore provides a mocked implementation of interface domain.HostStore
type MockHostStore struct {
	hostStore            []*hvs.Host
	HostFlavorgroupStore []*hvs.HostFlavorgroup
}

// Create inserts a Host
func (store *MockHostStore) Create(host *hvs.Host) (*hvs.Host, error) {
	store.hostStore = append(store.hostStore, host)
	return host, nil
}

// Retrieve returns Host
func (store *MockHostStore) Retrieve(id uuid.UUID, criteria *models.HostInfoFetchCriteria) (*hvs.Host, error) {
	for _, h := range store.hostStore {
		if h.Id == id {
			return h, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Update modifies a Host
func (store *MockHostStore) Update(host *hvs.Host) error {
	for i, h := range store.hostStore {
		if h.Id == host.Id {
			store.hostStore[i] = host
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// Delete deletes Host
func (store *MockHostStore) Delete(id uuid.UUID) error {
	for i, h := range store.hostStore {
		if h.Id == id {
			store.hostStore[i] = &hvs.Host{}
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

func (store *MockHostStore) DeleteByHostName(hostName string) error {
	for i, h := range store.hostStore {
		if h.HostName == hostName {
			store.hostStore[i] = &hvs.Host{}
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// Search returns a collection of Hosts filtered as per HostFilterCriteria
func (store *MockHostStore) Search(criteria *models.HostFilterCriteria, hostInfoFetchCriteria *models.HostInfoFetchCriteria) ([]*hvs.Host, error) {
	if criteria == nil || reflect.DeepEqual(*criteria, models.HostFilterCriteria{}) || reflect.DeepEqual(*criteria, models.HostFilterCriteria{Limit: 1000, AfterId: 0}) {
		return store.hostStore, nil
	}

	var hosts []*hvs.Host
	if criteria.Id != uuid.Nil {
		h, _ := store.Retrieve(criteria.Id, hostInfoFetchCriteria)
		if h != nil {
			hosts = append(hosts, h)
		}
	} else if criteria.HostHardwareId != uuid.Nil {
		for _, h := range store.hostStore {
			if *h.HardwareUuid == criteria.HostHardwareId {
				hosts = append(hosts, h)
			}
		}
	} else if criteria.NameEqualTo != "" {
		if criteria.NameEqualTo == "Search_Error" {
			return nil, errors.New("Error in searching host")
		}
		for _, h := range store.hostStore {
			if h.HostName == criteria.NameEqualTo {
				hosts = append(hosts, h)
			}
		}
	} else if criteria.NameContains != "" {
		for _, h := range store.hostStore {
			if strings.Contains(h.HostName, criteria.NameContains) {
				hosts = append(hosts, h)
			}
		}
	} else if criteria.Limit == 1 || criteria.AfterId == 1 {
		hosts = store.hostStore[:1]
	}
	return hosts, nil
}

// AddFlavorgroups associate a Host with specified flavorgroups
func (store *MockHostStore) AddFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	for _, fgId := range fgIds {
		store.HostFlavorgroupStore = append(store.HostFlavorgroupStore, &hvs.HostFlavorgroup{
			HostId:        hId,
			FlavorgroupId: fgId,
		})
	}
	return nil
}

// RetrieveFlavorgroup returns Host Flavorgroup association
func (store *MockHostStore) RetrieveFlavorgroup(hId, fgId uuid.UUID) (*hvs.HostFlavorgroup, error) {
	for _, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId && hf.FlavorgroupId == fgId {
			return hf, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// RemoveFlavorgroups delete Host Flavorgroup associations
func (store *MockHostStore) RemoveFlavorgroups(hId uuid.UUID, fgIds []uuid.UUID) error {
	for i, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId {
			for _, fgId := range fgIds {
				if hf.FlavorgroupId == fgId {
					store.HostFlavorgroupStore[i] = &hvs.HostFlavorgroup{}
					return nil
				}
			}
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// SearchFlavorgroups returns a collection of flavorgroup Ids associated with host Id
func (store *MockHostStore) SearchFlavorgroups(hId uuid.UUID) ([]uuid.UUID, error) {
	var fgIds []uuid.UUID
	for _, hf := range store.HostFlavorgroupStore {
		if hf.HostId == hId {
			fgIds = append(fgIds, hf.FlavorgroupId)
		}
	}
	return fgIds, nil
}

func (store *MockHostStore) AddTrustCacheFlavors(uuid.UUID, []uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}

func (store *MockHostStore) RemoveTrustCacheFlavors(uuid.UUID, []uuid.UUID) error {
	// TODO: to be implemented
	return nil
}

func (store *MockHostStore) RetrieveTrustCacheFlavors(_, _ uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}

func (store *MockHostStore) AddHostUniqueFlavors(uuid.UUID, []uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}
func (store *MockHostStore) RemoveHostUniqueFlavors(uuid.UUID, []uuid.UUID) error {
	// TODO: to be implemented
	return nil
}

func (store *MockHostStore) RetrieveHostUniqueFlavors(uuid.UUID) ([]uuid.UUID, error) {
	// TODO: to be implemented
	return nil, nil
}

func (store *MockHostStore) RetrieveDistinctUniqueFlavorParts(uuid.UUID) ([]string, error) {
	// TODO: to be implemented
	return nil, nil
}

// NewMockHostStore provides two dummy data for Hosts
func NewMockHostStore() *MockHostStore {
	store := &MockHostStore{}

	uuid1 := uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d")
	uuid2 := uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2")

	_, err := store.Create(&hvs.Host{
		Id:               uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		HostName:         "localhost1",
		HardwareUuid:     &uuid1,
		ConnectionString: "intel:https://ta.ip.com:1443",
		Description:      "Intel Host",
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Host")
	}

	_, err = store.Create(&hvs.Host{
		Id:               uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		HostName:         "localhost2",
		HardwareUuid:     &uuid2,
		ConnectionString: "vmware:https://vsphere.com:443/sdk;h=hostName;u=admin.local;p=password",
		Description:      "Vmware Host",
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Host")
	}

	err = store.AddFlavorgroups(uuid2, []uuid.UUID{uuid1})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error adding host to flavorgroup")
	}
	return store
}
