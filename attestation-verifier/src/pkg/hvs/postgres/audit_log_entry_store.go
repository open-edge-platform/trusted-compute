/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/pkg/errors"
)

type auditLogEntryStore struct {
	store *DataStore
}

func NewAuditLogEntryStore(s *DataStore) domain.AuditLogEntryStore {
	return &auditLogEntryStore{store: s}
}

func (as *auditLogEntryStore) Create(entry *models.AuditLogEntry) (*models.AuditLogEntry, error) {
	defaultLog.Trace("postgres/audit_log_entry_store_store:Create() Entering")
	defer defaultLog.Trace("postgres/audit_log_entry_store_store:Create() Leaving")

	if entry == nil ||
		entry.EntityID == uuid.Nil ||
		entry.Action == "" ||
		entry.Data.Columns == nil {
		return nil, errors.New("invalid audit log entry for audit_log_entry_store_store:Create()")
	}
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new UUID")
	}
	entry.ID = newUuid
	dbEntry := auditLogEntry{
		ID:         entry.ID,
		EntityID:   entry.EntityID,
		EntityType: entry.EntityType,
		CreatedAt:  time.Now(),
		Action:     entry.Action,
		Data:       PGAuditLogData(entry.Data),
	}
	if err := as.store.Db.Create(&dbEntry).Error; err != nil {
		return nil, errors.Wrap(err, "failed to create audit log entry in db")
	}
	return entry, nil
}

func (as *auditLogEntryStore) Retrieve(entry *models.AuditLogEntry) ([]models.AuditLogEntry, error) {
	defaultLog.Trace("postgres/audit_log_entry_store_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/audit_log_entry_store_store:Retrieve() Leaving")

	if entry == nil {
		return nil, errors.New("invalid audit log entry for audit_log_entry_store_store:Retrieve()")
	}
	if entry.ID == uuid.Nil &&
		entry.EntityID == uuid.Nil &&
		entry.Action == "" &&
		entry.EntityType == "" {
		return nil, errors.New("invalid audit log entry for audit_log_entry_store_store:Retrieve()")
	}
	dbFind := auditLogEntry{
		ID:         entry.ID,
		EntityID:   entry.EntityID,
		EntityType: entry.EntityType,
		Action:     entry.Action,
	}
	var matchEntries []auditLogEntry
	as.store.Db.Model(&auditLogEntry{}).Where(&dbFind).Find(&matchEntries)
	if as.store.Db.Error != nil {
		return nil, errors.Wrap(as.store.Db.Error, "failed to retrieve records from database")
	}
	var ret []models.AuditLogEntry
	for _, e := range matchEntries {
		eModel := models.AuditLogEntry{
			ID:         e.ID,
			EntityID:   e.EntityID,
			EntityType: e.EntityType,
			CreatedAt:  e.CreatedAt,
			Action:     e.Action,
			Data:       models.AuditTableData(e.Data),
		}
		ret = append(ret, eModel)
	}
	return ret, nil
}

func (as *auditLogEntryStore) Update(entry *models.AuditLogEntry) (*models.AuditLogEntry, error) {
	defaultLog.Trace("postgres/audit_log_entry_store_store:Update() Entering")
	defer defaultLog.Trace("postgres/audit_log_entry_store_store:Update() Leaving")

	if entry == nil ||
		entry.ID == uuid.Nil {
		return nil, errors.New("invalid audit log entry for audit_log_entry_store_store:Update()")
	}
	dbEntry := auditLogEntry{
		ID:         entry.ID,
		EntityID:   entry.EntityID,
		EntityType: entry.EntityType,
		CreatedAt:  time.Time{},
		Action:     entry.Action,
		Data:       PGAuditLogData(entry.Data),
	}
	if err := as.store.Db.Updates(&dbEntry).Error; err != nil {
		return nil, errors.Wrap(err, "failed to update audit log entry in db")
	}
	return entry, nil
}

func (as *auditLogEntryStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/audit_log_entry_store_store:Delete() Entering")
	defer defaultLog.Trace("postgres/audit_log_entry_store_store:Delete() Leaving")

	if err := as.store.Db.Delete(&auditLogEntry{ID: id}).Error; err != nil {
		return errors.Wrap(err, "failed to delete audit log entry from db: entry UUID: "+id.String())
	}
	return nil
}

func (as *auditLogEntryStore) FindBetweenTime(from, to time.Time) ([]models.AuditLogEntry, error) {
	defaultLog.Trace("postgres/audit_log_entry_store_store:FindBetweenTime() Entering")
	defer defaultLog.Trace("postgres/audit_log_entry_store_store:FindBetweenTime() Leaving")

	var matchEntries []auditLogEntry
	as.store.Db.Model(&auditLogEntry{}).Where("created_at BETWEEN ? AND ?", from, to).Find(&matchEntries)
	var ret []models.AuditLogEntry
	for _, e := range matchEntries {
		eModel := models.AuditLogEntry{
			ID:         e.ID,
			EntityID:   e.EntityID,
			EntityType: e.EntityType,
			CreatedAt:  e.CreatedAt,
			Action:     e.Action,
			Data:       models.AuditTableData(e.Data),
		}
		ret = append(ret, eModel)
	}
	return ret, nil
}
