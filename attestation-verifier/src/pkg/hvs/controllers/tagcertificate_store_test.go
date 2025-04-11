/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTagCertificateStore_Search_NilTx(t *testing.T) {
	plainTCStore := &postgres.TagCertificateStore{Store: &postgres.DataStore{Db: nil}}
	newId, err := uuid.NewRandom()
	assert.NoError(t, err)
	_, err = plainTCStore.Search(&models.TagCertificateFilterCriteria{ID: newId})
	assert.Error(t, err, "Expected nil result")
}

func TestTagCertificateStore_Search_ScanErrorHandle(t *testing.T) {
	mockTCS := mocks.NewMockTagCertificateStore()
	tcCols := []string{"id", "certificate", "subject", "issuer", "notbefore", "notafter", "hardwareuuid"}
	tcRow := []string{"7ce60664-faa3-4c2e-8c45-41e209e4f1db", "badcert", "00e4d709-8d72-44c3-89ae-c5edc395d6fe", "CN=asset-tag-service", "2015-09-28T09:08:33.913Z", "2050-09-28T09:08:33.913Z", "00e4d709-8d72-44c3-89ae-c5edc395d6fe"}
	// search by non-existent id
	newId, err := uuid.NewRandom()
	assert.NoError(t, err)
	mockTCS.Mock.ExpectQuery(`SELECT \* FROM "tag_certificate"  WHERE \(id = \$1\)`).
		WithArgs(newId).
		WillReturnRows(sqlmock.NewRows(tcCols).AddRow(tcRow[0], tcRow[1], tcRow[2], tcRow[3], tcRow[4], tcRow[5], tcRow[6]))

	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	_, err = mockTCS.Search(&models.TagCertificateFilterCriteria{ID: newUuid})
	assert.Error(t, err, "TagCertificate Store: Expected scan to throw error")
}
