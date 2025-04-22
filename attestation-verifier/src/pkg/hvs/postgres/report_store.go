/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type ReportStore struct {
	Store          *DataStore
	AuditLogWriter domain.AuditLogWriter
	dbLock         sync.Mutex
}

func NewReportStore(store *DataStore) *ReportStore {
	return &ReportStore{Store: store}
}

// Retrieve method fetches report for a given Id
func (r *ReportStore) Retrieve(reportId uuid.UUID) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/report_store:Retrieve() Leaving")

	re := models.HVSReport{}

	row := r.Store.Db.Model(&report{}).Where(&report{ID: reportId}).Row()
	ignoreMe := false //The new 'Trusted' field was introduced to v3.5, ignore that field in the query so it returns the correct results
	if err := row.Scan(&re.ID, &re.HostID, (*PGTrustReport)(&re.TrustReport), &ignoreMe, &re.CreatedAt, &re.Expiration, &re.Saml, &re.RowId); err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Retrieve() failed to scan record")
	}

	return &re, nil
}

// Update method is called after completion of flavor verification process by the flavor verify queue
func (r *ReportStore) Update(re *models.HVSReport) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Update() Entering")
	defer defaultLog.Trace("postgres/report_store:Update() Leaving")

	var refilter models.ReportFilterCriteria
	if re.HostID == uuid.Nil {
		return nil, errors.New("Host ID must be specified")
	} else {
		refilter = models.ReportFilterCriteria{
			HostID:        re.HostID,
			LatestPerHost: true,
		}
	}

	var vsReport *models.HVSReport
	r.dbLock.Lock()
	defer r.dbLock.Unlock()
	hvsReports, err := r.Search(&refilter)
	if err != nil {
		return nil, errors.Wrapf(err, "postgres/report_store:Update() Error while retrieving report for hostId %s", refilter.HostID)
	}

	// length of hvsReports will always be 1 for a given host ID
	if len(hvsReports) == 1 {
		err := r.Delete(hvsReports[0].ID)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:Update() Error while deleting report")
		}
	}

	vsReport, err = r.Create(re)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Update() Error while creating report")
	}
	return vsReport, nil
}

// Create method creates a new record in report table
func (r *ReportStore) Create(re *models.HVSReport) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Create() Entering")
	defer defaultLog.Trace("postgres/report_store:Create() Leaving")

	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Create() failed to create new UUID")
	}
	re.ID = newUuid
	dbReport := report{
		ID:          re.ID,
		HostID:      re.HostID,
		CreatedAt:   re.CreatedAt,
		Expiration:  re.Expiration,
		Saml:        re.Saml,
		TrustReport: PGTrustReport(re.TrustReport),
		Trusted:     re.TrustReport.Trusted,
	}
	if err := r.Store.Db.Create(&dbReport).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:Create() failed to create HVSReport")
	}
	// log to audit log
	if r.AuditLogWriter != nil {
		auditEntry, err := r.AuditLogWriter.CreateEntry("create", re)
		if err == nil {
			r.AuditLogWriter.Log(auditEntry)
		}
	}
	return re, nil
}

// Search retrieves collection of HVSReport pertaining to a user-provided ReportFilterCriteria
func (r *ReportStore) Search(criteria *models.ReportFilterCriteria) ([]models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:Search() Entering")
	defer defaultLog.Trace("postgres/report_store:Search() Leaving")

	var reportID uuid.UUID
	var hostID uuid.UUID
	var hostName string
	var hostHardwareUUID uuid.UUID
	var hostStatus string
	var latestPerHost bool
	var toDate time.Time
	var fromDate time.Time

	if criteria.ID != uuid.Nil {
		reportID = criteria.ID
	}
	if criteria.HostID != uuid.Nil {
		hostID = criteria.HostID
	}
	if criteria.HostHardwareID != uuid.Nil {
		hostHardwareUUID = criteria.HostHardwareID
	}
	if criteria.HostStatus != "" {
		hostStatus = criteria.HostStatus
	}
	if criteria.HostName != "" {
		hostName = criteria.HostName
	}
	if !criteria.ToDate.IsZero() {
		toDate = criteria.ToDate
	}
	if !criteria.FromDate.IsZero() {
		fromDate = criteria.FromDate
	}
	if criteria.Limit == 0 && criteria.LatestPerHost {
		criteria.Limit = constants.Limit
	}
	latestPerHost = criteria.LatestPerHost

	if criteria.NumberOfDays != 0 {
		toDate = time.Now().UTC()
		fromDate = toDate.AddDate(0, 0, -(criteria.NumberOfDays)).UTC()
	}

	var tx *gorm.DB
	if fromDate.IsZero() && toDate.IsZero() && criteria.LatestPerHost {
		tx = buildLatestReportSearchQuery(r.Store.Db, reportID, hostID, hostHardwareUUID, hostName, hostStatus, criteria.Limit, criteria.AfterId)

		if tx == nil {
			return nil, errors.New("postgres/report_store:Search() Unexpected Error. Could not build" +
				" a gorm query object in HVSReport Search function.")
		}

		rows, err := tx.Rows()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:Search() failed to retrieve records from db")
		}
		defer func() {
			derr := rows.Close()
			if derr != nil {
				defaultLog.WithError(derr).Error("Error closing rows")
			}
		}()

		var reports []models.HVSReport

		for rows.Next() {
			result := models.HVSReport{}
			ignoreMe := false //The new 'Trusted' field was introduced to v3.5, ignore that field in the query so it returns the correct results
			if err := rows.Scan(&result.ID, &result.HostID, (*PGTrustReport)(&result.TrustReport), &ignoreMe, &result.CreatedAt, &result.Expiration, &result.Saml, &result.RowId); err != nil {
				return nil, errors.Wrap(err, "postgres/report_store:Search() failed to scan record")
			}
			reports = append(reports, result)
		}

		return reports, nil
	} else {
		tx = buildReportSearchQuery(r.Store.Db, hostID, hostHardwareUUID, hostName, hostStatus, fromDate, toDate, latestPerHost, criteria.Limit, criteria.AfterId)
		if tx == nil {
			return nil, errors.New("postgres/report_store:Search() Unexpected Error. Could not build" +
				" a gorm query object in HVSReport Search function.")
		}

		rows, err := tx.Rows()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:Search() failed to retrieve records from db")
		}
		defer func() {
			derr := rows.Close()
			if derr != nil {
				defaultLog.WithError(derr).Error("Error closing rows")
			}
		}()

		var reports []models.HVSReport
		for rows.Next() {
			result := models.AuditLogEntry{}
			if err := rows.Scan(&result.ID, &result.EntityID, &result.EntityType, &result.CreatedAt, &result.Action, (*PGAuditLogData)(&result.Data), &result.RowId); err != nil {
				return nil, errors.Wrap(err, "postgres/report_store:Search() failed to scan record")
			}
			if reflect.DeepEqual(models.AuditTableData{}, result.Data) || len(result.Data.Columns) == 0 {
				continue
			}
			hvsReport, err := auditlogEntryToReport(result)
			if err != nil {
				return nil, errors.Wrap(err, "postgres/report_store:Search() convert auditloag entry into report")
			}
			reports = append(reports, *hvsReport)
		}

		return reports, nil
	}
}

// FindHostIdsFromExpiredReports searches the report table for reports that have an
// 'expiration' between 'fromTime' and 'toTime'.
// It also discovers hosts that do not have a corresponding report in the table.
func (r *ReportStore) FindHostIdsFromExpiredReports(fromTime time.Time, toTime time.Time) ([]uuid.UUID, error) {

	var tx *gorm.DB
	tx = r.Store.Db.Raw("SELECT h.id from host h "+
		"INNER JOIN report r ON h.id = r.host_id "+
		"WHERE CAST(expiration AS TIMESTAMP) > CAST(? AS TIMESTAMP) "+
		"AND CAST(expiration AS TIMESTAMP) <= CAST(? AS TIMESTAMP) "+
		"AND h.id NOT IN (SELECT CAST(params ->> 'host_id' AS uuid) from queue) "+
		"UNION "+
		"SELECT h.id FROM host h LEFT JOIN report r ON h.id = r.host_id "+
		"WHERE r.id IS NULL", fromTime, toTime)
	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/report_store:FindHostIdsFromExpiredReports() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var hostIDs []uuid.UUID
	for rows.Next() {
		hostID := uuid.UUID{}
		if err := rows.Scan(&hostID); err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:FindHostIdsFromExpiredReports() failed to scan record")
		}
		hostIDs = append(hostIDs, hostID)
	}
	return hostIDs, nil
}

func auditlogEntryToReport(auRecord models.AuditLogEntry) (*models.HVSReport, error) {
	defaultLog.Trace("postgres/report_store:auditlogEntryToReport() Entering")
	defer defaultLog.Trace("postgres/report_store:auditlogEntryToReport() Leaving")

	var hvsReport models.HVSReport

	if auRecord.EntityID != uuid.Nil {
		hvsReport.ID = auRecord.EntityID
	}
	// TODO remove duplicate data: first column and the entityID are both same
	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[1]) && auRecord.Data.Columns[1].Value != nil {
		hostId, err := uuid.Parse(fmt.Sprintf("%v", auRecord.Data.Columns[1].Value))
		if err != nil {
			return nil, errors.Wrap(err, "postgres/report_store:auditlogEntryToReport() - parsing hostid failed")
		}
		hvsReport.HostID = hostId
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[2]) && auRecord.Data.Columns[2].Value != nil {
		c, err := json.Marshal(auRecord.Data.Columns[2].Value)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/reports_store:auditlogEntryToReport() - marshalling failed")
		}
		err = json.Unmarshal(c, &hvsReport.TrustReport)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/reports_store:auditlogEntryToReport() - unmarshalling failed")
		}
	}

	var err error
	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[3]) && auRecord.Data.Columns[3].Value != nil {
		createdString := fmt.Sprintf("%v", auRecord.Data.Columns[3].Value)
		hvsReport.CreatedAt, err = time.Parse(time.RFC3339Nano, createdString)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/reports_store:auditlogEntryToReport() - error parsing time")
		}
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[4]) && auRecord.Data.Columns[4].Value != nil {
		expString := fmt.Sprintf("%v", auRecord.Data.Columns[4].Value)
		hvsReport.Expiration, err = time.Parse(time.RFC3339Nano, expString)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/reports_store:auditlogEntryToReport() - error parsing time")
		}
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[5]) && auRecord.Data.Columns[5].Value != nil {
		hvsReport.Saml = fmt.Sprintf("%v", auRecord.Data.Columns[5].Value)
	}

	return &hvsReport, nil
}

// Delete method deletes report for a given Id
func (r *ReportStore) Delete(reportId uuid.UUID) error {
	defaultLog.Trace("postgres/report_store:Delete() Entering")
	defer defaultLog.Trace("postgres/report_store:Delete() Leaving")
	// get the deleted record
	re := report{}
	r.Store.Db.Where(&report{ID: reportId}).First(&re)

	if err := r.Store.Db.Delete(&report{ID: reportId}).Error; err != nil {
		return errors.Wrap(err, "postgres/report_store:Delete() failed to delete Report")
	}
	// log to audit log
	if r.AuditLogWriter != nil {
		auditEntry, err := r.AuditLogWriter.CreateEntry("delete", re)
		if err == nil {
			r.AuditLogWriter.Log(auditEntry)
		}
	}
	return nil
}

// buildReportSearchQuery is a helper function to build the query object for a report search.
func buildReportSearchQuery(tx *gorm.DB, hostHardwareID, hostID uuid.UUID, hostName, hostState string, fromDate, toDate time.Time, latestPerHost bool, limit int, afterId int) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Entering")
	defer defaultLog.Trace("postgres/report_store:buildReportSearchQuery() Leaving")
	if tx == nil {
		return nil
	}
	if latestPerHost {
		entity := "auj"
		txSubQuery := tx.Table("audit_log_entry auj").
			Select("data -> 'Columns' -> 1 ->> 'Value' AS host_id, max(auj.created) AS max_date")

		txSubQuery = buildReportSearchQueryWithCriteria(txSubQuery, hostHardwareID, hostID, entity, hostName, hostState, fromDate, toDate)
		txSubQuery = txSubQuery.Group("host_id")

		subQuery := txSubQuery
		tx = tx.Table("audit_log_entry au").Select("au.*").Joins("INNER JOIN (?) a ON a.host_id = au.data -> 'Columns' -> 1 ->> 'Value' AND a.max_date = au.created", subQuery)
	} else {
		entity := "au"
		tx = tx.Table("audit_log_entry au").Select("au.*")
		tx = buildReportSearchQueryWithCriteria(tx, hostHardwareID, hostID, entity, hostName, hostState, fromDate, toDate)
	}

	if afterId > 0 {
		tx = tx.Where("rowid > ?", afterId)
	}
	tx = tx.Order("rowid asc")
	if limit > 0 {
		tx = tx.Limit(limit)
	}
	return tx
}

func buildReportSearchQueryWithCriteria(tx *gorm.DB, hostHardwareID, hostID uuid.UUID, entity, hostName string, hostState string, fromDate, toDate time.Time) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildReportSearchQueryWithCriteria() Entering")
	defer defaultLog.Trace("postgres/report_store:buildReportSearchQueryWithCriteria() Leaving")

	if hostState != "" {
		tx = tx.Joins("INNER JOIN host_status hs on CAST(hs.host_id AS VARCHAR) = " + entity + ".data -> 'Columns' -> 1 ->> 'Value'")
	}

	if hostName != "" || hostHardwareID != uuid.Nil {
		tx = tx.Joins("INNER JOIN host h on CAST(h.id AS VARCHAR) = " + entity + ".data -> 'Columns' -> 1 ->> 'Value'")
	}

	//TODO rename after testing
	tx = tx.Where(entity + ".entity_type = 'report'")

	if hostName != "" {
		tx = tx.Where("h.name = ?", hostName)
	}

	if hostHardwareID != uuid.Nil {
		tx = tx.Where("h.hardware_uuid = ?", hostHardwareID.String())
	}

	if hostID != uuid.Nil {
		tx = tx.Where(entity+".data -> 'Columns' -> 1 ->> 'Value' = ?", hostID.String())
	}

	if hostState != "" {
		tx = tx.Where("hs.status ->> 'host_state' = ?", strings.ToUpper(hostState))
	}

	if !fromDate.IsZero() {
		tx = tx.Where("CAST("+entity+".created AS TIMESTAMP) >= CAST(? AS TIMESTAMP)", fromDate)
	}

	if !toDate.IsZero() {
		tx = tx.Where("CAST("+entity+".created AS TIMESTAMP) < CAST(? AS TIMESTAMP)", toDate)
	}

	return tx
}

// buildLatestReportSearchQuery is a helper function to build the query object for a latest report search.
func buildLatestReportSearchQuery(tx *gorm.DB, reportID, hostID, hostHardwareID uuid.UUID, hostName, hostState string, limit int, afterId int) *gorm.DB {
	defaultLog.Trace("postgres/report_store:buildLatestReportSearchQuery() Entering")
	defer defaultLog.Trace("postgres/report_store:buildLatestReportSearchQuery() Leaving")

	if tx == nil {
		return nil
	}
	tx = tx.Model(&report{})

	// Since report id is unique and only one record can be returned by the query.
	if reportID != uuid.Nil {
		tx = tx.Where("id = ?", reportID.String())
		return tx
	}

	if hostID != uuid.Nil || hostName != "" || hostHardwareID != uuid.Nil {
		tx = tx.Joins("INNER JOIN host h on h.id = host_id")
	}

	if hostState != "" {
		tx = tx.Joins("INNER JOIN host_status hs on hs.host_id = report.host_id")
		tx = tx.Where(`hs.status ->> 'host_state'=?`, strings.ToUpper(hostState))
	}

	if hostName != "" {
		tx = tx.Where("h.name = ?", hostName)
	}

	if hostHardwareID != uuid.Nil {
		tx = tx.Where("h.hardware_uuid = ?", hostHardwareID.String())
	}

	if hostID != uuid.Nil {
		tx = tx.Where("host_id = ?", hostID.String())
	}

	if afterId > 0 {
		tx = tx.Where("rowid > ?", afterId)
	}

	tx = tx.Order("rowid asc")

	if limit > 0 {
		tx = tx.Limit(limit)
	}

	return tx
}
