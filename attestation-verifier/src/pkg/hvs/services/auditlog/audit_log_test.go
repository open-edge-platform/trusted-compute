/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package auditlog

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

type mockEntryStore struct {
	data map[string]*models.AuditLogEntry
	t    *testing.T
}

func (me *mockEntryStore) Create(e *models.AuditLogEntry) (*models.AuditLogEntry, error) {
	id, _ := uuid.NewRandom()
	e.ID = id
	me.data[id.String()] = e
	me.t.Log("Create", e)
	return e, nil
}

func (me *mockEntryStore) Retrieve(e *models.AuditLogEntry) ([]models.AuditLogEntry, error) {
	if e.ID == uuid.Nil &&
		e.EntityID == uuid.Nil &&
		e.Action == "" &&
		e.EntityType == "" {
		return nil, errors.New("invalid argument for retrieve")
	}
	var ret []models.AuditLogEntry
	for _, v := range me.data {
		add := true
		add = e.ID == uuid.Nil || v.ID == e.ID
		add = e.EntityID == uuid.Nil || v.EntityID == e.EntityID
		add = e.Action == "" || v.Action == e.Action
		add = e.EntityType == "" || v.EntityType == e.EntityType
		if add {
			ret = append(ret, *v)
		}
	}
	me.t.Log("Retrieve", e)
	return ret, nil
}

func (me *mockEntryStore) Update(e *models.AuditLogEntry) (*models.AuditLogEntry, error) {
	if e.ID == uuid.Nil {
		return nil, errors.New("id can not be nil")
	}
	if _, ok := me.data[e.ID.String()]; !ok {
		return nil, errors.New("record not found")
	}
	me.data[e.ID.String()] = e
	me.t.Log("Update", e)
	return e, nil
}

func (me *mockEntryStore) Delete(id uuid.UUID) error {
	if _, ok := me.data[id.String()]; !ok {
		return errors.New("record not found")
	}
	delete(me.data, id.String())
	me.t.Log("Delete", id.String())
	return nil
}

func TestAuditLogService(t *testing.T) {
	store := &mockEntryStore{
		t:    t,
		data: make(map[string]*models.AuditLogEntry),
	}
	w, err := NewAuditLogDBWriter(nil, 100)
	if err == nil {
		t.Error("Error not returned for nil store audit log service")
	}
	w, err = NewAuditLogDBWriter(store, 100)
	if err != nil {
		t.Error("can not configure audit log service")
		t.Error(err)
	}
	hs, r, err := testWorkers(w, t)
	if err != nil {
		t.Error("failed to start all test routines")
		t.Error(err)
	}
	w.Stop()
	// check if things are there
	t.Log(store.data)
	for _, hostStatus := range hs {
		filter := &models.AuditLogEntry{
			EntityID: hostStatus.ID,
		}
		if ans, err := store.Retrieve(filter); err != nil {
			findEID := hostStatus.ID.String()
			t.Log(findEID)
			if len(ans) == 0 {
				t.Error("record not found in mock db")
			} else {
				if ans[0].EntityID.String() != findEID {
					t.Error("record not found in mock db")
				}
			}
		}
	}
	for _, report := range r {
		filter := &models.AuditLogEntry{
			EntityID: report.ID,
		}
		if ans, err := store.Retrieve(filter); err != nil {
			findEID := report.ID.String()
			t.Log(findEID)
			if len(ans) == 0 {
				t.Error("record not found in mock db")
			} else {
				if ans[0].EntityID.String() != findEID {
					t.Error("record not found in mock db")
				}
			}
		}
	}
}

func testWorkers(w domain.AuditLogWriter, t *testing.T) (hs []*hvs.HostStatus, r []*models.HVSReport, err error) {
	// init test data
	hostStatTestCnt := 5
	ReportTestCnt := 5

	ops := []string{"create", "retrieve", "update", "delete"}
	syncChan := make(chan struct{}, hostStatTestCnt+ReportTestCnt)

	for i := 1; i <= hostStatTestCnt; i++ {
		newId, err := uuid.NewRandom()
		assert.NoError(t, err)
		hostId, err := uuid.NewRandom()
		assert.NoError(t, err)
		hs = append(hs, &hvs.HostStatus{
			ID:     newId,
			HostID: hostId,
		})
	}

	for i := 1; i <= ReportTestCnt; i++ {
		newId, err := uuid.NewRandom()
		assert.NoError(t, err)
		hostId, err := uuid.NewRandom()
		assert.NoError(t, err)
		r = append(r, &models.HVSReport{
			ID:     newId,
			HostID: hostId,
		})
	}
	// add to audit log in parallel
	for i := 0; i < hostStatTestCnt; i++ {
		go func(idx int) {
			randRange, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				t.Error("failed to get random number")
				t.Error(err)
				return
			}
			op := ops[randRange.Int64()]
			e, err := w.CreateEntry(op, hs[idx], hs[idx])
			if err != nil {
				t.Error("create entry failed")
				t.Error(err)
				return
			}
			w.Log(e)
			syncChan <- struct{}{}
			t.Log(e)
		}(i)
	}

	for i := 0; i < ReportTestCnt; i++ {
		go func(idx int) {
			randRange, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				t.Error("failed to get random number")
				t.Error(err)
				return
			}
			op := ops[randRange.Int64()]
			e, err := w.CreateEntry(op, r[idx], r[idx])
			if err != nil {
				t.Error("create entry failed")
				t.Error(err)
				return
			}
			w.Log(e)
			syncChan <- struct{}{}
			t.Log(e)
		}(i)
	}

	// sync all routine
	for i := 1; i <= hostStatTestCnt+ReportTestCnt; i++ {
		<-syncChan
	}
	return
}
