/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strings"
)

type TpmEndorsementStore struct {
	Store *DataStore
}

func NewTpmEndorsementStore(store *DataStore) *TpmEndorsementStore {
	return &TpmEndorsementStore{store}
}

func (t *TpmEndorsementStore) Create(te *hvs.TpmEndorsement) (*hvs.TpmEndorsement, error) {
	defaultLog.Trace("postgres/tpm_endorsement_store:Create() Entering")
	defer defaultLog.Trace("postgres/tpm_endorsement_store:Create() Leaving")
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Create() failed to create new UUID")
	}
	te.ID = newUuid

	dbTpmEndorsement := tpmEndorsement{
		ID:                te.ID,
		HardwareUUID:      te.HardwareUUID,
		Issuer:            strings.Replace(te.Issuer, " ", "", -1),
		Revoked:           te.Revoked,
		Certificate:       te.Certificate,
		Comment:           te.Comment,
		CertificateDigest: te.CertificateDigest,
	}

	if err := t.Store.Db.Create(&dbTpmEndorsement).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Create() failed to create TpmEndorsement")
	}

	return te, nil
}

func (t *TpmEndorsementStore) Update(te *hvs.TpmEndorsement) (*hvs.TpmEndorsement, error) {
	dbTpmEndorsement := tpmEndorsement{
		ID:                te.ID,
		HardwareUUID:      te.HardwareUUID,
		Issuer:            strings.Replace(te.Issuer, " ", "", -1),
		Revoked:           te.Revoked,
		Certificate:       te.Certificate,
		Comment:           te.Comment,
		CertificateDigest: te.CertificateDigest,
	}
	if err := t.Store.Db.Save(&dbTpmEndorsement).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Update() failed to save TpmEndorsement")
	}
	return te, nil
}

func (t *TpmEndorsementStore) Retrieve(id uuid.UUID) (*hvs.TpmEndorsement, error) {
	defaultLog.Trace("postgres/tpm_endorsement_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/tpm_endorsement_store:Retrieve() Leaving")

	row := t.Store.Db.Model(tpmEndorsement{}).Where(tpmEndorsement{ID: id}).Row()
	te := hvs.TpmEndorsement{}
	if err := row.Scan(&te.ID, &te.HardwareUUID, &te.Issuer, &te.Revoked, &te.Certificate, &te.Comment, &te.CertificateDigest, &te.RowId); err != nil {
		return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Retrieve() - Could not scan record ")
	}

	return &te, nil
}

func (t *TpmEndorsementStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/tpm_endorsement_store:Delete() Entering")
	defer defaultLog.Trace("postgres/tpm_endorsement_store:Delete() Leaving")

	if err := t.Store.Db.Delete(&tpmEndorsement{ID: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/tpm_endorsement_store:Delete() failed to delete TpmEndorsement")
	}
	return nil
}

func (t *TpmEndorsementStore) Search(teFilter *models.TpmEndorsementFilterCriteria) (*hvs.TpmEndorsementCollection, error) {
	defaultLog.Trace("postgres/tpm_endorsement_store:Search() Entering")
	defer defaultLog.Trace("postgres/tpm_endorsement_store:Search() Leaving")

	tx := buildTpmEndorsementSearchQuery(t.Store.Db, teFilter)

	if tx == nil {
		return nil, errors.New("postgres/tpm_endorsement_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in Endorsement Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Search() failed to retrieve tpm_endorsements from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var tpmEndorsementCollection hvs.TpmEndorsementCollection

	for rows.Next() {
		te := hvs.TpmEndorsement{}
		if err := rows.Scan(&te.ID, &te.HardwareUUID, &te.Issuer, &te.Revoked, &te.Certificate, &te.Comment, &te.CertificateDigest, &te.RowId); err != nil {
			return nil, errors.Wrap(err, "postgres/tpm_endorsement_store:Search() - Could not scan record ")
		}
		tpmEndorsementCollection.TpmEndorsement = append(tpmEndorsementCollection.TpmEndorsement, &te)
	}

	return &tpmEndorsementCollection, nil
}

func buildTpmEndorsementSearchQuery(tx *gorm.DB, teFilter *models.TpmEndorsementFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/tpm_endorsement_store:buildTpmEndorsementSearchQuery() Entering")
	defer defaultLog.Trace("postgres/tpm_endorsement_store:buildTpmEndorsementSearchQuery() Leaving")

	if tx == nil {
		return nil
	}
	tx = tx.Model(&tpmEndorsement{})
	if teFilter == nil {
		defaultLog.Info("postgres/tpm_endorsement_store:buildTpmEndorsementSearchQuery() No criteria specified in search query" +
			". Returning all rows.")
		return tx
	}
	tx = tx.Where("revoked = ? ", teFilter.RevokedEqualTo)
	if teFilter.Id != uuid.Nil {
		tx = tx.Where("id = ?", teFilter.Id)
	} else if teFilter.IssuerEqualTo != "" {
		tx = tx.Where("issuer = ?", teFilter.IssuerEqualTo)
	} else if teFilter.CommentContains != "" {
		tx = tx.Where("comment like ? ", "%"+teFilter.CommentContains+"%")
	} else if teFilter.CommentEqualTo != "" {
		tx = tx.Where("comment = ? ", teFilter.CommentEqualTo)
	} else if teFilter.HardwareUuidEqualTo != uuid.Nil {
		tx = tx.Where("hardware_uuid = ? ", teFilter.HardwareUuidEqualTo)
	} else if teFilter.IssuerContains != "" {
		tx = tx.Where("issuer like ? ", "%"+teFilter.IssuerContains+"%")
	} else if teFilter.CertificateDigestEqualTo != "" {
		tx = tx.Where("certificate_digest = ? ", teFilter.CertificateDigestEqualTo)
	}
	if teFilter.Limit == 0 {
		teFilter.Limit = consts.Limit
	}

	if teFilter.AfterId > 0 {
		tx = tx.Where("rowid > ?", teFilter.AfterId)
	}
	tx = tx.Order("rowid asc")
	if teFilter.Limit > 0 {
		tx = tx.Limit(teFilter.Limit)
	}
	return tx
}
