/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package auditlog

import (
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	log "github.com/sirupsen/logrus"
	"runtime/debug"
	"sync"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/pkg/errors"
)

type auditLogDB struct {
	store domain.AuditLogEntryStore

	numAdded int
	logQueue chan *models.AuditLogEntry
	stopChan chan struct{}
	doneChan chan struct{}
	lock     sync.Mutex
}

var defaultLog = commLog.GetDefaultLogger()

func NewAuditLogDBWriter(s domain.AuditLogEntryStore, chanBufferSize int) (domain.AuditLogWriter, error) {
	if s == nil {
		return nil, errors.New("NewAuditLogPostgresService: invalid datastore")
	}
	ret := &auditLogDB{
		store: s,
	}
	ret.logQueue = make(chan *models.AuditLogEntry, chanBufferSize)
	ret.stopChan = make(chan struct{})
	ret.doneChan = make(chan struct{})
	if err := ret.startCreateRoutine(); err != nil {
		return nil, errors.Wrap(err, "failed to start audit log creation routine")
	}
	return ret, nil
}

func (alp *auditLogDB) Log(e *models.AuditLogEntry) { alp.logQueue <- e }

func (alp *auditLogDB) Stop() {
	alp.stopChan <- struct{}{}
	<-alp.doneChan
	close(alp.stopChan)
	close(alp.doneChan)
}

func (alp *auditLogDB) startCreateRoutine() error {
	if alp.stopChan == nil ||
		alp.logQueue == nil {
		return errors.New("auditLogDB: channel cannot be nil")
	}
	go func() {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
				defaultLog.Error(string(debug.Stack()))
			}
		}()
		for {
			select {
			case e := <-alp.logQueue:
				_, err := alp.store.Create(e)
				if err != nil {
					log.WithError(err).Errorf("failed to create audit log routine")
				}
			case <-alp.stopChan:
				// clean existing queue and return
				for len(alp.logQueue) > 0 {
					e := <-alp.logQueue
					_, err := alp.store.Create(e)
					if err != nil {
						log.WithError(err).Errorf("failed to create audit log routine")
					}
				}
				alp.doneChan <- struct{}{}
				return
			}
		}
	}()
	return nil
}
