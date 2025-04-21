/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

type (
	FlavorGroupStore interface {
		Create(*hvs.FlavorGroup) (*hvs.FlavorGroup, error)
		Retrieve(uuid.UUID) (*hvs.FlavorGroup, error)
		Search(*models.FlavorGroupFilterCriteria) ([]hvs.FlavorGroup, error)
		Delete(uuid.UUID) error
		HasAssociatedHosts(uuid.UUID) (bool, error)
		AddFlavors(uuid.UUID, []uuid.UUID) ([]uuid.UUID, error)
		RemoveFlavors(uuid.UUID, []uuid.UUID) error
		SearchFlavors(uuid.UUID) ([]uuid.UUID, error)
		RetrieveFlavor(uuid.UUID, uuid.UUID) (*hvs.FlavorgroupFlavorLink, error)
		SearchHostsByFlavorGroup(fgID uuid.UUID) ([]uuid.UUID, error)
		SearchFlavorTemplatesByFlavorGroup(fgID uuid.UUID) ([]uuid.UUID, error)
		GetFlavorTypesInFlavorGroup(flvGrpId uuid.UUID) (map[hvs.FlavorPartName]bool, error)
		AddFlavorTemplates(uuid.UUID, []uuid.UUID) error
	}

	HostStore interface {
		Create(*hvs.Host) (*hvs.Host, error)
		Retrieve(uuid.UUID, *models.HostInfoFetchCriteria) (*hvs.Host, error)
		Update(*hvs.Host) error
		Delete(uuid.UUID) error
		DeleteByHostName(string) error
		Search(*models.HostFilterCriteria, *models.HostInfoFetchCriteria) ([]*hvs.Host, error)
		AddFlavorgroups(uuid.UUID, []uuid.UUID) error
		RetrieveFlavorgroup(uuid.UUID, uuid.UUID) (*hvs.HostFlavorgroup, error)
		RemoveFlavorgroups(uuid.UUID, []uuid.UUID) error
		SearchFlavorgroups(uuid.UUID) ([]uuid.UUID, error)
		AddTrustCacheFlavors(uuid.UUID, []uuid.UUID) ([]uuid.UUID, error)
		RemoveTrustCacheFlavors(uuid.UUID, []uuid.UUID) error
		// RetrieveTrustCacheFlavors function takes in host UUID and a flavorgroup uuid. The reason for this
		// is the trust cache is associated to a flavor group.
		RetrieveTrustCacheFlavors(uuid.UUID, uuid.UUID) ([]uuid.UUID, error)
		// Flavors that are unique to the host such as HOST_UNIQUE and ASSET_TAG should have an association
		// with the host.

		AddHostUniqueFlavors(hId uuid.UUID, fIds []uuid.UUID) ([]uuid.UUID, error)
		RemoveHostUniqueFlavors(hId uuid.UUID, fIds []uuid.UUID) error
		RetrieveHostUniqueFlavors(hId uuid.UUID) ([]uuid.UUID, error)
		RetrieveDistinctUniqueFlavorParts(hId uuid.UUID) ([]string, error)
	}

	HostCredentialStore interface {
		Create(*models.HostCredential) (*models.HostCredential, error)
		Retrieve(uuid.UUID) (*models.HostCredential, error)
		Update(*models.HostCredential) error
		Delete(uuid.UUID) error
		FindByHostId(uuid.UUID) (*models.HostCredential, error)
		FindByHostName(string) (*models.HostCredential, error)
	}

	FlavorStore interface {
		Create(*hvs.SignedFlavor) (*hvs.SignedFlavor, error)
		Retrieve(uuid.UUID) (*hvs.SignedFlavor, error)
		Search(*models.FlavorVerificationFC) ([]hvs.SignedFlavor, error)
		Delete(uuid.UUID) error
	}

	TpmEndorsementStore interface {
		Create(*hvs.TpmEndorsement) (*hvs.TpmEndorsement, error)
		Update(*hvs.TpmEndorsement) (*hvs.TpmEndorsement, error)
		Retrieve(uuid.UUID) (*hvs.TpmEndorsement, error)
		Search(*models.TpmEndorsementFilterCriteria) (*hvs.TpmEndorsementCollection, error)
		Delete(uuid.UUID) error
	}

	// FlavorTemplateStore will do the DB operations related to flavor template CRUD.
	FlavorTemplateStore interface {
		Create(*hvs.FlavorTemplate) (*hvs.FlavorTemplate, error)
		Retrieve(uuid.UUID, bool) (*hvs.FlavorTemplate, error)
		Search(*models.FlavorTemplateFilterCriteria) ([]hvs.FlavorTemplate, error)
		Delete(uuid.UUID) error
		Recover([]string) error
		AddFlavorgroups(uuid.UUID, []uuid.UUID) error
		RetrieveFlavorgroup(uuid.UUID, uuid.UUID) (*hvs.FlavorTemplateFlavorgroup, error)
		RemoveFlavorgroups(uuid.UUID, []uuid.UUID) error
		SearchFlavorgroups(uuid.UUID) ([]uuid.UUID, error)
	}

	// HostStatusStore specifies the DB operations that must be implemented for the Host Status API
	HostStatusStore interface {
		Create(*hvs.HostStatus) (*hvs.HostStatus, error)
		Retrieve(uuid.UUID) (*hvs.HostStatus, error)
		Search(*models.HostStatusFilterCriteria) ([]hvs.HostStatus, error)
		Delete(uuid.UUID) error
		Persist(*hvs.HostStatus) error
		FindHostIdsByKeyValue(key, value string) ([]uuid.UUID, error)
	}

	QueueStore interface {
		Search(*models.QueueFilterCriteria) ([]*models.Queue, error)
		Retrieve(uuid.UUID) (*models.Queue, error)
		Update(*models.Queue) error
		Create(*models.Queue) (*models.Queue, error)
		Delete(uuid.UUID) error
	}

	ReportStore interface {
		Search(*models.ReportFilterCriteria) ([]models.HVSReport, error)
		Retrieve(uuid.UUID) (*models.HVSReport, error)
		Create(*models.HVSReport) (*models.HVSReport, error)
		Update(*models.HVSReport) (*models.HVSReport, error)
		Delete(uuid.UUID) error
		FindHostIdsFromExpiredReports(fromTime time.Time, toTime time.Time) ([]uuid.UUID, error)
	}

	// TagCertificateStore enumerates the operations expected to be performed on a TagCertificate backend
	TagCertificateStore interface {
		Create(*hvs.TagCertificate) (*hvs.TagCertificate, error)
		Retrieve(uuid.UUID) (*hvs.TagCertificate, error)
		Delete(uuid.UUID) error
		Search(*models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error)
	}

	HostTrustManager interface {
		// Verify the trust of the a host.
		//Returns the host trust report. For now marking this as interface since we have not defined the report structure
		VerifyHost(hostId uuid.UUID, fetchHostData bool, preferHashMatch bool) (*models.HVSReport, error)

		// This method is an asynchronous method meant to do the verify the trust of the host
		// asynchronously. The requests are persisted to Store in case the server is taken down.
		// Parameters:
		// hostIds - slice of hosts id whose trust should be verified
		// fetchHostData - Fetch a new Manifest/Data from the host.
		// preferHashMatch - Can attempt to do match a cumulative hash from the Host Manifest/ Data rather than
		//                   doing a full report.
		VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error

		//Process all records stuck in queue post service restart
		ProcessQueue() error
	}

	HostDataReceiver interface {
		ProcessHostData(ctx context.Context, host hvs.Host, data *hvs.HostManifest, preferHashMatch bool, err error) error
	}

	HostDataFetcher interface {
		// Synchronous method that blocks till the data is retrieved from the host.
		Retrieve(host hvs.Host) (*hvs.HostManifest, error)

		// Asynchronous method to be used to fetch data from hosts. As soon as the request is registered,
		// the method returns. The result is returned individually as they are processed.
		// We need the single host method a there is a need to cancel individual host fetch
		// using the context
		RetrieveAsync(ctx context.Context, host hvs.Host, preferHashMatch bool, rcvrs ...HostDataReceiver) error

		// TODO: ? Do we need a method that can use used to pass in a list rather than one at a time
		// RetrieveMultipleAsync(context.Context, []*hvs.Host, rcvrs ...HostDataReceiver) error
	}

	HostTrustVerifier interface {
		Verify(hostId uuid.UUID, hostData *hvs.HostManifest, newData bool, preferHashMatch bool) (*models.HVSReport, error)
	}

	AuditLogWriter interface {
		// creates an entry of auditlog
		CreateEntry(string, ...interface{}) (*models.AuditLogEntry, error)
		// add entry to audit log
		Log(*models.AuditLogEntry)
		Stop()
	}

	AuditLogEntryStore interface {
		Create(*models.AuditLogEntry) (*models.AuditLogEntry, error)
		Retrieve(*models.AuditLogEntry) ([]models.AuditLogEntry, error)
		Update(*models.AuditLogEntry) (*models.AuditLogEntry, error)
		Delete(uuid.UUID) error
	}
)
