/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"encoding/json"
	"io/ioutil"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// MockReportStore provides a mocked implementation of interface postgres.ReportStore
type MockReportStore struct {
	reportStore map[uuid.UUID]models.HVSReport
}

// Create inserts a HVSReport
func (store *MockReportStore) Create(report *models.HVSReport) (*models.HVSReport, error) {
	if report.ID == uuid.Nil {
		newUuid, err := uuid.NewRandom()
		if err != nil {
			return nil, err
		}
		report.ID = newUuid
	}
	store.reportStore[report.ID] = *report
	return report, nil
}

func (store *MockReportStore) Update(report *models.HVSReport) (*models.HVSReport, error) {
	store.reportStore[report.ID] = *report
	return report, nil
}

// Retrieve returns HVSReport
func (store *MockReportStore) Retrieve(id uuid.UUID) (*models.HVSReport, error) {
	if rs, found := store.reportStore[id]; found {
		return &rs, nil
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Delete deletes HVSReport
func (store *MockReportStore) Delete(id uuid.UUID) error {
	for _, t := range store.reportStore {
		if t.ID == id {
			delete(store.reportStore, id)
		}
	}
	return errors.New("record not found")
}

//Search returns a collection of HVSReports filtered as per ReportFilterCriteria
func (store *MockReportStore) Search(criteria *models.ReportFilterCriteria) ([]models.HVSReport, error) {
	if criteria == nil || reflect.DeepEqual(*criteria, models.ReportFilterCriteria{}) {

		return nil, nil
	}
	hostStore := NewMockHostStore()
	hostStatusStore := NewMockHostStatusStore()
	var reports []models.HVSReport
	var hosts []*hvs.Host
	var hostStatuses []hvs.HostStatus
	if criteria.ID != uuid.Nil {
		r, _ := store.Retrieve(criteria.ID)
		if r != nil {
			reports = append(reports, *r)
		}
	} else if criteria.HostHardwareID != uuid.Nil || criteria.HostName != "" {
		for _, t := range hostStore.hostStore {
			if criteria.HostHardwareID == *t.HardwareUuid || criteria.HostName == t.HostName {
				hosts = append(hosts, t)
			}
		}
		for _, h := range hosts {
			for _, r := range store.reportStore {
				if h.Id == r.HostID {
					reports = append(reports, r)
				}
			}
		}
	} else if criteria.HostID != uuid.Nil {
		for _, r := range store.reportStore {
			if criteria.HostID == r.HostID {
				reports = append(reports, r)
			}
		}
	} else if criteria.HostStatus != "" {
		hostStatuses, _ = hostStatusStore.Search(&models.HostStatusFilterCriteria{
			HostStatus:    criteria.HostStatus,
			LatestPerHost: true,
		})

		for _, h := range hostStatuses {
			for _, r := range store.reportStore {
				if h.HostID == r.HostID {
					reports = append(reports, r)
				}
			}
		}
	} else if !criteria.ToDate.IsZero() {
		for _, r := range store.reportStore {
			if r.Expiration.Before(criteria.ToDate) {
				reports = append(reports, r)
			}
		}
	} else if criteria.Limit == 1 || criteria.AfterId == 1 {
		for _, r := range store.reportStore {
			reports = append(reports, r)
		}
		reports = reports[:1]
	} else {
		// criteria is all empty return all records
		for _, r := range store.reportStore {
			reports = append(reports, r)
		}
	}

	return reports, nil
}

func (store *MockReportStore) FindHostIdsFromExpiredReports(fromTime time.Time, toTime time.Time) ([]uuid.UUID, error) {
	hostIDs := []uuid.UUID{}

	for _, r := range store.reportStore {
		if r.Expiration.After(fromTime) && r.Expiration.Before(toTime) {
			hostIDs = append(hostIDs, r.HostID)
		}
	}

	return hostIDs, nil
}

// NewMockReportStore provides two dummy data for Reports
func NewMockReportStore() *MockReportStore {
	//TODO add more data
	store := &MockReportStore{}
	store.reportStore = make(map[uuid.UUID]models.HVSReport)
	saml1text, _ := ioutil.ReadFile("../domain/mocks/resources/saml_report")
	trustReportBytes, _ := ioutil.ReadFile("../domain/mocks/resources/trust_report.json")
	var trustReport hvs.TrustReport
	err := json.Unmarshal(trustReportBytes, &trustReport)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error unmarshalling trust report")
	}
	created, _ := time.Parse(constants.ParamDateTimeFormat, "2020-06-21 07:18:00.57")
	expiration, _ := time.Parse(constants.ParamDateTimeFormat, "2020-06-22 07:18:00.57")
	_, err = store.Create(&models.HVSReport{
		ID:          uuid.MustParse("15701f03-7b1d-49f9-ac62-6b9b0728bdb3"),
		HostID:      uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"),
		CreatedAt:   created,
		Expiration:  expiration,
		Saml:        string(saml1text),
		TrustReport: trustReport,
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Trust Report")
	}

	_, err = store.Create(&models.HVSReport{
		ID:          uuid.MustParse("15701f03-7b1d-49f9-ac62-6b9b0728bdb4"),
		HostID:      uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"),
		CreatedAt:   created,
		Expiration:  expiration,
		Saml:        string(saml1text),
		TrustReport: trustReport,
	})
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Trust Report")
	}
	return store
}

func NewEmptyMockReportStore() domain.ReportStore {
	store := MockReportStore{}
	store.reportStore = make(map[uuid.UUID]models.HVSReport)
	return &store
}
