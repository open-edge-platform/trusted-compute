/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package auditlog

import (
	"reflect"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

var (
	AuditLogTag   = "json"
	NameDelimiter = "."
)

func (alp *auditLogDB) CreateEntry(action string, values ...interface{}) (*models.AuditLogEntry, error) {
	if len(values) < 1 {
		return nil, errors.New("invalid input for audit log: nothing provided")
	}
	if action == "update" &&
		len(values) != 2 {
		return nil, errors.New("invalid input for audit log: not enough input")
	}
	var ok bool
	switch base := values[0].(type) {
	default:
		return nil, errors.New("type not supported for audit log")
	case *hvs.HostStatus:
		diff := base
		if action == "update" {
			if diff, ok = values[1].(*hvs.HostStatus); !ok {
				return nil, errors.New("invalid input for audit log: incoherent input")
			}
		}
		cols := hostStatus2Cols(base, diff)
		if cols == nil {
			return nil, errors.New("error when traversing structure")
		}
		return entryHelper(base.ID, "host_status", action, cols), nil
	case *models.HVSReport:
		diff := base
		var cols []models.AuditColumnData
		if action == "update" {
			if diff, ok = values[1].(*models.HVSReport); !ok {
				return nil, errors.New("invalid input for audit log: incoherent input")
			}
		}
		cols = append(cols, report2Cols(base, diff)...)
		return entryHelper(base.ID, "report", action, cols), nil
	}
}

func entryHelper(eID uuid.UUID, eType, action string, cols []models.AuditColumnData) *models.AuditLogEntry {
	return &models.AuditLogEntry{
		EntityID:   eID,
		EntityType: eType,
		Action:     action,
		Data: models.AuditTableData{
			Columns: cols,
		},
	}
}

func report2Cols(old, current *models.HVSReport) []models.AuditColumnData {
	return []models.AuditColumnData{
		{
			Name:      "id",
			Value:     current.ID,
			IsUpdated: old.ID != current.ID,
		},
		{
			Name:      "host_id",
			Value:     current.HostID,
			IsUpdated: old.HostID != current.HostID,
		},
		{
			Name:      "trust_report",
			Value:     current.TrustReport,
			IsUpdated: !reflect.DeepEqual(old.TrustReport, current.TrustReport),
		},
		{
			Name:      "created",
			Value:     current.CreatedAt,
			IsUpdated: old.CreatedAt != current.CreatedAt,
		},
		{
			Name:      "expiration",
			Value:     current.Expiration,
			IsUpdated: old.Expiration != current.Expiration,
		},
		{
			Name:      "saml",
			Value:     current.Saml,
			IsUpdated: old.Saml != current.Saml,
		},
	}
}

func hostStatus2Cols(old, current *hvs.HostStatus) []models.AuditColumnData {
	return []models.AuditColumnData{
		{
			Name:      "id",
			Value:     current.ID,
			IsUpdated: old.ID != current.ID,
		},
		{
			Name:      "host_id",
			Value:     current.HostID,
			IsUpdated: old.HostID != current.HostID,
		},
		{
			Name:      "status",
			Value:     current.HostStatusInformation,
			IsUpdated: !reflect.DeepEqual(old.HostStatusInformation, current.HostStatusInformation),
		},
		{
			Name:      "host_report",
			Value:     current.HostManifest,
			IsUpdated: !reflect.DeepEqual(old.HostManifest, current.HostManifest),
		},
		{
			Name:      "created",
			Value:     current.Created,
			IsUpdated: old.Created != current.Created,
		},
	}
}
