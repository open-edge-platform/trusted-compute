/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/pkg/errors"
	"time"
)

type HostCredentialStore struct {
	Store *DataStore
	Dek   []byte
}

func NewHostCredentialStore(store *DataStore, dek []byte) *HostCredentialStore {
	return &HostCredentialStore{
		Store: store,
		Dek:   dek,
	}
}

func (hcs *HostCredentialStore) Create(hc *models.HostCredential) (*models.HostCredential, error) {
	defaultLog.Trace("postgres/host_credential_store:Create() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:Create() Leaving")

	encCred, err := utils.EncryptString(hc.Credential, hcs.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:Create() failed to encrypt Host Credential")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:Create() failed to create new UUID")
	}
	hc.Id = newUuid
	dbHostCredential := hostCredential{
		Id:           hc.Id,
		HostId:       hc.HostId,
		HostName:     hc.HostName,
		HardwareUuid: hc.HardwareUuid,
		Credential:   encCred,
		CreatedTs:    time.Now(),
	}

	if err := hcs.Store.Db.Create(&dbHostCredential).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:Create() failed to create Host Credential")
	}
	return hc, nil
}

func (hcs *HostCredentialStore) Retrieve(id uuid.UUID) (*models.HostCredential, error) {
	defaultLog.Trace("postgres/host_credential_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:Retrieve() Leaving")

	hc := models.HostCredential{}
	row := hcs.Store.Db.Model(&hostCredential{}).Where(&hostCredential{Id: id}).Row()
	if err := row.Scan(&hc.Id, &hc.HostId, &hc.HostName, &hc.HardwareUuid, &hc.Credential, &hc.CreatedTs); err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:Retrieve() failed to scan record")
	}

	var err error
	hc.Credential, err = utils.DecryptString(hc.Credential, hcs.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:Retrieve() failed to decrypt credentials")
	}
	return &hc, nil
}

func (hcs *HostCredentialStore) Update(hc *models.HostCredential) error {
	defaultLog.Trace("postgres/host_credential_store:Update() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:Update() Leaving")

	if hc.Credential != "" {
		encCred, err := utils.EncryptString(hc.Credential, hcs.Dek)
		if err != nil {
			return errors.Wrap(err, "postgres/host_credential_store:Update() failed to encrypt Host Credential")
		}
		hc.Credential = encCred
	}

	dbHostCredential := hostCredential{
		Id:           hc.Id,
		HostId:       hc.HostId,
		HostName:     hc.HostName,
		HardwareUuid: hc.HardwareUuid,
		Credential:   hc.Credential,
		CreatedTs:    time.Now(),
	}

	if db := hcs.Store.Db.Model(&dbHostCredential).Updates(&dbHostCredential); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return errors.Wrap(db.Error, "postgres/host_credential_store:Update() failed to update Host Credential  "+dbHostCredential.Id.String())
		} else {
			return errors.New("postgres/host_credential_store:Update() - no rows affected - Record not found = id :  " + dbHostCredential.Id.String())
		}
	}
	return nil
}

func (hcs *HostCredentialStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/host_credential_store:Delete() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:Delete() Leaving")

	if err := hcs.Store.Db.Delete(&hostCredential{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/host_credential_store:Delete() failed to delete Host Credential")
	}
	return nil
}

func (hcs *HostCredentialStore) FindByHostId(id uuid.UUID) (*models.HostCredential, error) {
	defaultLog.Trace("postgres/host_credential_store:FindByHostId() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:FindByHostId() Leaving")

	hc := models.HostCredential{}
	row := hcs.Store.Db.Model(&hostCredential{}).Where(&hostCredential{HostId: id}).Row()
	if err := row.Scan(&hc.Id, &hc.HostId, &hc.HostName, &hc.HardwareUuid, &hc.Credential, &hc.CreatedTs); err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:FindByHostId() failed to scan record")
	}

	var err error
	hc.Credential, err = utils.DecryptString(hc.Credential, hcs.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:FindByHostId() failed to decrypt credentials")
	}
	return &hc, nil
}

func (hcs *HostCredentialStore) FindByHostName(name string) (*models.HostCredential, error) {
	defaultLog.Trace("postgres/host_credential_store:FindByHostName() Entering")
	defer defaultLog.Trace("postgres/host_credential_store:FindByHostName() Leaving")

	hc := models.HostCredential{}
	row := hcs.Store.Db.Model(&hostCredential{}).Where(&hostCredential{HostName: name}).Row()
	if err := row.Scan(&hc.Id, &hc.HostId, &hc.HostName, &hc.HardwareUuid, &hc.Credential, &hc.CreatedTs); err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:FindByHostName() failed to scan record")
	}

	var err error
	hc.Credential, err = utils.DecryptString(hc.Credential, hcs.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/host_credential_store:FindByHostName() failed to decrypt credentials")
	}
	return &hc, nil
}
