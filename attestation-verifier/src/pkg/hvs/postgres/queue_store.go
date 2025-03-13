/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"github.com/pkg/errors"
)

type QueueStore struct {
	store *DataStore
}

func NewDBQueueStore(store *DataStore) domain.QueueStore {

	return &QueueStore{store}
}

func (qr *QueueStore) Create(q *models.Queue) (*models.Queue, error) {

	defaultLog.Trace("postgres/queue_store:Create() Entering")
	defer defaultLog.Trace("postgres/queue_store:Create() Leaving")
	if q == nil || q.Action == "" || len(q.Params) == 0 || !q.State.Valid() {
		return nil, errors.New("postgres/queue_store:Create()- invalid input  must have Action, Parameter and valid State")
	}

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/queue_store:Create() failed to create new UUID")
	}
	dbq := queue{Id: newUuid,
		Action:    q.Action,
		State:     q.State,
		Message:   q.Message,
		Params:    PGJsonStrMap(q.Params),
		CreatedAt: time.Now().UTC(),
	}

	if err := qr.store.Db.Create(&dbq).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/queue_store:Create() failed to create Queue Entry")
	}
	//update the id in the outgoing data structure.
	q.Id = dbq.Id
	return q, nil
}

func (qr *QueueStore) Retrieve(id uuid.UUID) (*models.Queue, error) {
	defaultLog.Trace("postgres/queue_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/queue_store:Retrieve() Leaving")
	row := qr.store.Db.Model(&queue{}).Where(&queue{Id: id}).Row()
	q := models.Queue{}
	if err := row.Scan(&q.Id, &q.Action, (*PGJsonStrMap)(&q.Params), &q.Created, &q.Updated, &q.State, &q.Message); err != nil {
		return nil, errors.Wrap(err, "postgres/queue_store:Retrieve() - Could not scan record")
	}

	return &q, nil
}

func (qr *QueueStore) Search(qf *models.QueueFilterCriteria) ([]*models.Queue, error) {
	defaultLog.Trace("postgres/queue_store:RetrieveAll() Entering")
	defer defaultLog.Trace("postgres/queue_store:RetrieveAll() Leaving")

	tx := buildQueueSearchQuery(qr.store.Db, qf)

	if tx == nil {
		return nil, errors.New("postgres/queue_store:RetrieveAll() Unexpected Error. Could not build" +
			" a gorm query object in Queues RetrieveAll function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/queue_store:RetrieveAll() failed to retrieve queues from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()
	result := []*models.Queue{}

	for rows.Next() {
		q := models.Queue{}
		if err := rows.Scan(&q.Id, &q.Action, (*PGJsonStrMap)(&q.Params), &q.Created, &q.Updated, &q.State, &q.Message); err != nil {
			return nil, errors.Wrap(err, "postgres/queue_store:Retrieve() - Could not scan record ")
		}
		result = append(result, &q)
	}

	return result, nil
}

func (qr *QueueStore) Update(q *models.Queue) error {
	defaultLog.Trace("postgres/queue_store:Update() Entering")
	defer defaultLog.Trace("postgres/queue_store:Update() Leaving")

	if q.Id == uuid.Nil {
		return errors.New("postgres/queue_store:Update() - Id is invalid")
	}

	dbq := queue{Id: q.Id,
		Action:    q.Action,
		State:     q.State,
		Message:   q.Message,
		CreatedAt: q.Created,
		UpdatedAt: time.Now().UTC(),
	}
	if q.Params != nil {
		dbq.Params = q.Params
	}
	if db := qr.store.Db.Model(&dbq).Updates(&dbq); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return errors.Wrap(db.Error, "postgres/queue_store:Update() failed to update Queue  "+q.Id.String())
		} else {
			return errors.New("postgres/queue_store:Update() - no rows affected - Record not found = id :  " + q.Id.String())
		}

	}
	return nil
}

func (qr *QueueStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/queue_store:Delete() Entering")
	defer defaultLog.Trace("postgres/queue_store:Delete() Leaving")

	if id == uuid.Nil {
		return errors.New("postgres/queue_store:Update() - Id is invalid")
	}
	if err := qr.store.Db.Delete(&queue{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/queue_store:Delete() failed to delete Queue")
	}
	return nil
}

// helper function to build the query object for a Queue search.
func buildQueueSearchQuery(tx *gorm.DB, qf *models.QueueFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/queue_store:buildQueueSearchQuery() Entering")
	defer defaultLog.Trace("postgres/queue_store:buildQueueSearchQuery() Leaving")

	if tx == nil {
		return nil
	}
	tx = tx.Model(&queue{})
	if qf == nil {
		return tx
	}
	if qf.Id != uuid.Nil {
		tx = tx.Where(&queue{Id: qf.Id})
	}
	if qf.Action != "" {
		tx = tx.Where("action = ?", qf.Action)

		if qf.ParamKey != "" && qf.ParamValue != "" {
			tx = tx.Where("params ->> ? = ?", qf.ParamKey, qf.ParamValue)
		} else if len(qf.ParamMap) > 0 {
			for k, v := range qf.ParamMap {
				tx = tx.Where("params ->> ? = ?", k, v)
			}
		}
	}
	if len(qf.QueueStates) > 0 {
		tx = tx.Where("state in (?)", qf.QueueStates)
	}

	// apply limit
	if qf.Limit > 0 {
		tx = tx.Limit(qf.Limit)
	}

	return tx
}
