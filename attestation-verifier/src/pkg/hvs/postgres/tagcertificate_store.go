/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

// TagCertificateStore holds the reference to the backend store for the TagCertificate controller
type TagCertificateStore struct {
	Store *DataStore
}

// NewTagCertificateStore is a constructor method that initializes a TagCertificate store
func NewTagCertificateStore(store *DataStore) *TagCertificateStore {
	return &TagCertificateStore{store}
}

// Create creates a new TagCertificate record in the backend store
func (tcs *TagCertificateStore) Create(tc *hvs.TagCertificate) (*hvs.TagCertificate, error) {
	defaultLog.Trace("postgres/tagcertificate_store:Create() Entering")
	defer defaultLog.Trace("postgres/tagcertificate_store:Create() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tagcertificate_store:Create() failed to create new UUID")
	}
	tc.ID = newUuid

	dbTagCert := &tagCertificate{
		ID:           tc.ID,
		HardwareUUID: tc.HardwareUUID,
		Certificate:  tc.Certificate,
		Subject:      tc.Subject,
		Issuer:       tc.Issuer,
		NotBefore:    tc.NotBefore,
		NotAfter:     tc.NotAfter,
	}

	if err := tcs.Store.Db.Create(&dbTagCert).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/tagcertificate_store:Create() failed to create TagCertificate")
	}

	return tc, nil
}

// Search returns a list of TagCertificates records per requested TagCertificateFilterCriteria
func (tcs *TagCertificateStore) Search(tcFilter *models.TagCertificateFilterCriteria) ([]*hvs.TagCertificate, error) {
	defaultLog.Trace("postgres/tagcertificate_store:Search() Entering")
	defer defaultLog.Trace("postgres/tagcertificate_store:Search() Leaving")

	var tcResultSet = []*hvs.TagCertificate{}

	tx := buildTagCertificateSearchQuery(tcs.Store.Db, tcFilter)

	if tx == nil {
		return nil, errors.New("postgres/tagcertificate_store:Search() Unexpected Error. Could not build" +
			" a gorm query object in TagCertificate Search function.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/tagcertificate_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	for rows.Next() {
		hvsTC := hvs.TagCertificate{}
		if err := rows.Scan(&hvsTC.ID, &hvsTC.HardwareUUID, &hvsTC.Certificate, &hvsTC.Subject, &hvsTC.Issuer, &hvsTC.NotBefore, &hvsTC.NotAfter); err != nil {
			return nil, errors.Wrap(err, "postgres/tagcertificate_store:Search() failed to scan record")
		}
		tcResultSet = append(tcResultSet, &hvsTC)
	}

	return tcResultSet, nil
}

// Retrieve returns a single TagCertificate record by unique ID
func (tcs *TagCertificateStore) Retrieve(tagCertId uuid.UUID) (*hvs.TagCertificate, error) {
	defaultLog.Trace("postgres/tagcertificate_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/tagcertificate_store:Retrieve() Leaving")

	hvsTC := hvs.TagCertificate{}
	row := tcs.Store.Db.Model(&tagCertificate{}).Where(&tagCertificate{ID: tagCertId}).Row()
	if err := row.Scan(&hvsTC.ID, &hvsTC.HardwareUUID, &hvsTC.Certificate, &hvsTC.Subject, &hvsTC.Issuer, &hvsTC.NotBefore, &hvsTC.NotAfter); err != nil {
		return nil, errors.Wrap(err, "postgres/tagcertificate_store:Retrieve() failed to scan record")
	}
	return &hvsTC, nil
}

func (tcs *TagCertificateStore) Delete(tagCertificateId uuid.UUID) error {
	defaultLog.Trace("postgres/tagcertificate_store:Delete() Entering")
	defer defaultLog.Trace("postgres/tagcertificate_store:Delete() Leaving")

	if err := tcs.Store.Db.Delete(&tagCertificate{ID: tagCertificateId}).Error; err != nil {
		return errors.Wrap(err, "postgres/tagcertificate_store:Delete() failed to delete TagCertificate")
	}
	return nil
}

// buildTagCertificateSearchQuery helper function to build the query object for a TagCertificate search.
func buildTagCertificateSearchQuery(tx *gorm.DB, tcFilter *models.TagCertificateFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/tagcertificate_store:buildTagCertificateSearchQuery() Entering")
	defer defaultLog.Trace("postgres/tagcertificate_store:buildTagCertificateSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&tagCertificate{})
	if tcFilter == nil {
		defaultLog.Info("postgres/tagcertificate_store:buildTagCertificateSearchQuery() No criteria specified in search query" +
			". Returning all rows.")
		return tx.Order("subject")
	}

	// Tag Certificate ID
	if tcFilter.ID != uuid.Nil {
		tx = tx.Where("id = ?", tcFilter.ID.String())
	}

	// SubjectEqualTo
	if tcFilter.SubjectEqualTo != "" {
		tx = tx.Where("lower(subject) = ?", strings.ToLower(tcFilter.SubjectEqualTo))
	}

	// SubjectContains
	if tcFilter.SubjectContains != "" {
		tx = tx.Where("lower(subject) like ?", "%"+strings.ToLower(tcFilter.SubjectContains)+"%")
	}

	// IssuerEqualTo
	if tcFilter.IssuerEqualTo != "" {
		tx = tx.Where("lower(issuer) = ?", strings.ToLower(tcFilter.IssuerEqualTo))
	}

	// IssuerContains
	if tcFilter.IssuerContains != "" {
		tx = tx.Where("lower(issuer) like ?", "%"+strings.ToLower(tcFilter.IssuerContains)+"%")
	}

	// hardware_uuid
	if tcFilter.HardwareUUID != uuid.Nil {
		tx = tx.Where("hardware_uuid = ?", tcFilter.HardwareUUID.String())
	}

	// ValidOn
	if !tcFilter.ValidOn.IsZero() {
		validOnTs := tcFilter.ValidOn.Format(constants.ParamDateTimeFormatUTC)
		tx = tx.Where("CAST(notbefore AS TIMESTAMP) <= CAST(? AS TIMESTAMP) AND CAST(? AS TIMESTAMP) <= CAST(notafter AS TIMESTAMP)", validOnTs, validOnTs)
	}

	if !tcFilter.ValidBefore.IsZero() {
		validBeforeTs := tcFilter.ValidBefore.Format(constants.ParamDateTimeFormatUTC)
		tx = tx.Where("CAST(? as timestamp) >= notbefore", validBeforeTs)
	}
	if !tcFilter.ValidAfter.IsZero() {
		validAfterTs := tcFilter.ValidAfter.Format(constants.ParamDateTimeFormatUTC)
		tx = tx.Where("CAST(? as timestamp) <= notafter", validAfterTs)
	}

	// ORDER BY
	tx = tx.Order("subject")

	return tx
}
