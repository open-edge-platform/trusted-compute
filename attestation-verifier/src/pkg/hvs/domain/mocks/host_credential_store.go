/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/pkg/errors"
)

// MockHostCredentialStore provides a mocked implementation of interface domain.HostCredentialStore
type MockHostCredentialStore struct {
	hostCredentialStore []*models.HostCredential
}

// Create inserts a HostCredential
func (store *MockHostCredentialStore) Create(host *models.HostCredential) (*models.HostCredential, error) {
	store.hostCredentialStore = append(store.hostCredentialStore, host)
	return host, nil
}

// Retrieve returns HostCredential
func (store *MockHostCredentialStore) Retrieve(id uuid.UUID) (*models.HostCredential, error) {
	for _, h := range store.hostCredentialStore {
		if h.Id == id {
			return h, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Update modifies a HostCredential
func (store *MockHostCredentialStore) Update(hostCredential *models.HostCredential) error {
	for i, h := range store.hostCredentialStore {
		if h.Id == hostCredential.Id {
			store.hostCredentialStore[i] = hostCredential
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// Delete deletes HostCredential
func (store *MockHostCredentialStore) Delete(id uuid.UUID) error {
	for i, h := range store.hostCredentialStore {
		if h.Id == id {
			store.hostCredentialStore[i] = &models.HostCredential{}
			return nil
		}
	}
	return errors.New(commErr.RecordNotFound)
}

// FindByHostId searches HostCredential by host Id
func (store *MockHostCredentialStore) FindByHostId(hostId uuid.UUID) (*models.HostCredential, error) {
	for _, h := range store.hostCredentialStore {
		if h.HostId == hostId {
			return h, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// FindByHostName searches HostCredential by host name
func (store *MockHostCredentialStore) FindByHostName(hostName string) (*models.HostCredential, error) {
	for _, h := range store.hostCredentialStore {
		if h.HostName == hostName {
			return h, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// NewMockHostCredentialStore provides empty data for HostCredentials
func NewMockHostCredentialStore() *MockHostCredentialStore {
	store := &MockHostCredentialStore{
		hostCredentialStore: []*models.HostCredential{&models.HostCredential{
			HostName:   "fakehost",
			Credential: "u=fakeuser;p=fakepass",
		},
		},
	}
	return store
}
