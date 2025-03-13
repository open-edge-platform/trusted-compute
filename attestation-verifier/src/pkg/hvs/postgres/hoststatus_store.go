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
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

type HostStatusStore struct {
	Store          *DataStore
	AuditLogWriter domain.AuditLogWriter
}

func NewHostStatusStore(store *DataStore) *HostStatusStore {
	return &HostStatusStore{Store: store}
}

// Create creates a HostStatus record in the DB
func (hss *HostStatusStore) Create(hs *hvs.HostStatus) (*hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:Create() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Create() Leaving")

	// populate realtime fields
	newUuid, err := uuid.NewRandom()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Create() failed to create new UUID")
	}
	hs.ID = newUuid
	hs.Created = time.Now()
	dbHostStatus := hostStatus{
		ID:         hs.ID,
		HostID:     hs.HostID,
		Status:     PGHostStatusInformation(hs.HostStatusInformation),
		HostReport: PGHostManifest(hs.HostManifest),
		CreatedAt:  hs.Created,
	}

	if err = hss.Store.Db.Create(&dbHostStatus).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Create() failed to create hostStatus")
	}
	// log to audit log
	if hss.AuditLogWriter != nil {
		auditEntry, err := hss.AuditLogWriter.CreateEntry("create", hs)
		if err == nil {
			hss.AuditLogWriter.Log(auditEntry)
		}
	}
	return hs, nil
}

// Retrieve retrieves a single HostStatus record matching a provided hostStatusId
func (hss *HostStatusStore) Retrieve(hostStatusId uuid.UUID) (*hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Retrieve() Leaving")

	row := hss.Store.Db.Model(&hostStatus{}).Where("id = ?", hostStatusId).Row()
	result := hvs.HostStatus{}
	if err := row.Scan(&result.ID, &result.HostID, (*PGHostStatusInformation)(&result.HostStatusInformation), (*PGHostManifest)(&result.HostManifest), &result.Created, &result.RowId); err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:Retrieve() failed to retrieve hostStatus")
	}

	return &result, nil
}

// Search retrieves a HostStatusCollection pertaining to a user-provided HostStatusFilterCriteria
func (hss *HostStatusStore) Search(hsFilter *models.HostStatusFilterCriteria) ([]hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:Search() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Search() Leaving")

	var tx *gorm.DB

	// setting to empty array
	hostStatuses := []hvs.HostStatus{}

	if hsFilter.FromDate.IsZero() && hsFilter.ToDate.IsZero() && hsFilter.LatestPerHost {
		tx = buildLatestHostStatusSearchQuery(hss.Store.Db, hsFilter)
		if tx == nil {
			return nil, errors.New("postgres/hoststatus_store:Search() Unexpected Error. Could not build" +
				" a gorm query object in HostStatus Search function.")
		}
		rows, err := tx.Rows()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to retrieve records from db")
		}
		defer func() {
			derr := rows.Close()
			if derr != nil {
				defaultLog.WithError(derr).Error("Error closing rows")
			}
		}()

		for rows.Next() {
			var result hvs.HostStatus

			if err := rows.Scan(&result.ID, &result.HostID, (*PGHostStatusInformation)(&result.HostStatusInformation), (*PGHostManifest)(&result.HostManifest), &result.Created, &result.RowId); err != nil {
				return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to scan record")
			}
			hostStatuses = append(hostStatuses, result)
		}
	} else {
		tx = buildHostStatusSearchQuery(hss.Store.Db, hsFilter)
		if tx == nil {
			return nil, errors.New("postgres/hoststatus_store:Search() Unexpected Error. Could not build" +
				" a gorm query object in HostStatus Search function.")
		}
		rows, err := tx.Rows()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to retrieve records from db")
		}
		defer func() {
			derr := rows.Close()
			if derr != nil {
				defaultLog.WithError(derr).Error("Error closing rows")
			}
		}()

		for rows.Next() {
			result := models.AuditLogEntry{}
			if err := rows.Scan(&result.ID, &result.EntityID, &result.EntityType, &result.CreatedAt, &result.Action, (*PGAuditLogData)(&result.Data), &result.RowId); err != nil {
				return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() failed to scan record")
			}
			if reflect.DeepEqual(models.AuditTableData{}, result.Data) || len(result.Data.Columns) == 0 {
				continue
			}
			hs, err := auditlogEntryToHostStatus(result)
			if err != nil {
				return nil, errors.Wrap(err, "postgres/hoststatus_store:Search() convert auditlog entry into HostStatus")
			}
			hostStatuses = append(hostStatuses, *hs)
		}
	}

	return hostStatuses, nil
}

// Persist is used by the HostDataFetcher to update an existing HostStatus record else create one if it does not exist
func (hss *HostStatusStore) Persist(hs *hvs.HostStatus) error {
	defaultLog.Trace("postgres/hoststatus_store:Persist() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Persist() Leaving")

	if hs.HostID == uuid.Nil {
		return errors.New("postgres/hoststatus_store:Persist() - HostID is missing")
	}

	// find record before update
	oldHs := &hostStatus{}
	err := hss.Store.Db.Where(&hostStatus{HostID: hs.HostID}).First(&oldHs).Error

	if err != nil {
		// record does not exist, then create
		_, err = hss.Create(hs)
		if err != nil {
			return errors.Wrap(err, "postgres/hoststatus_store:Persist() - Failed to Create HostStatus record ")
		} else {
			return nil
		}
	}

	// record already exists, update the record
	dbHostStatus := hostStatus{
		ID:         oldHs.ID,
		HostID:     oldHs.HostID,
		Status:     PGHostStatusInformation(hs.HostStatusInformation),
		HostReport: PGHostManifest(hs.HostManifest),
		CreatedAt:  time.Now(),
	}

	if db := hss.Store.Db.Model(&dbHostStatus).Updates(&dbHostStatus); db.Error != nil || db.RowsAffected != 1 {
		if db.Error != nil {
			return errors.Wrap(db.Error, "postgres/hoststatus_store:Persist() failed to update HostStatus  "+hs.ID.String())
		} else {
			return errors.New("postgres/hoststatus_store:Persist() - no rows affected - Record not found = id :  " + hs.ID.String())
		}

	}
	// log to audit log
	if hss.AuditLogWriter != nil {
		auditEntry, err := hss.AuditLogWriter.CreateEntry("update", oldHs, hs)
		if err == nil {
			hss.AuditLogWriter.Log(auditEntry)
		}
	}
	return nil
}

func (hss *HostStatusStore) Delete(hostStatusId uuid.UUID) error {
	defaultLog.Trace("postgres/hoststatus_store:Delete() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:Delete() Leaving")

	dbHostStatus := hostStatus{
		ID: hostStatusId,
	}
	deletedHs := hostStatus{}
	hss.Store.Db.Where(&dbHostStatus).First(&deletedHs)
	if err := hss.Store.Db.Delete(&dbHostStatus).Error; err != nil {
		return errors.Wrap(err, "postgres/hoststatus_store:Delete() failed to delete HostStatus")
	}
	// log to audit log
	if hss.AuditLogWriter != nil {
		auditEntry, err := hss.AuditLogWriter.CreateEntry("delete", deletedHs)
		if err == nil {
			hss.AuditLogWriter.Log(auditEntry)
		}
	}
	return nil
}

func (hss *HostStatusStore) FindHostIdsByKeyValue(key, value string) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/hoststatus_store:FindHostIdsByKeyValue() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:FindHostIdsByKeyValue() Leaving")

	rows, err := hss.Store.Db.Raw("SELECT host_id FROM host_status WHERE host_report::text != 'null' AND host_report -> 'host_info' ->> ? = ?", key, value).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/hoststatus_store:FindHostIdsByKeyValue() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var ids []uuid.UUID
	for rows.Next() {
		id := uuid.UUID{}
		if err := rows.Scan(&id); err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:FindHostIdsByKeyValue() failed to scan record")
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// buildHostStatusSearchQuery is a helper function to build the query object for a hostStatus search inlcuding results
// from audit table hostStatus records
func buildHostStatusSearchQuery(tx *gorm.DB, hsFilter *models.HostStatusFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/hoststatus_store:buildHostStatusSearchQuery() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:buildHostStatusSearchQuery() Leaving")

	var tableJoinString, additionalOptionsQueryString string

	// define joins
	auditLogAbbrv := "au"
	if hsFilter.LatestPerHost {
		auditLogAbbrv = "auj"
	}

	formattedQuery := "SELECT au.* FROM audit_log_entry au"

	additionalOptionsQueryString = fmt.Sprintf("WHERE %s.entity_type = 'host_status' ", auditLogAbbrv)

	// Build table join string with host table if host identifier is set
	if hsFilter.HostName != "" {
		tableJoinString = fmt.Sprintf("INNER JOIN host h on CAST(h.id AS VARCHAR) = %s.data -> 'Columns' -> 1 ->> 'Value'", auditLogAbbrv)
	}

	//Build additional options query string is table join string set
	if tableJoinString != "" {
		//Build host ID partial query string and add it to the additional options query string
		if hsFilter.HostId != uuid.Nil {
			hostIdQueryString := fmt.Sprintf("h.id = '%s'", hsFilter.HostId.String())
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostIdQueryString)
		}
		//calling hostIdentifierQueryString method to improve the performance by referring to the host table when host identifier is set
		if hsFilter.HostName != "" {
			hostNameQueryString := fmt.Sprintf("h.name = '%s'", hsFilter.HostName)
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostNameQueryString)
		}
		if hsFilter.HostHardwareId != uuid.Nil {
			hostHWUUIDQueryString := fmt.Sprintf("h.hardware_uuid = '%s'", hsFilter.HostHardwareId.String())
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostHWUUIDQueryString)
		}
	} else {
		//Build host ID partial query string and add it to the additional options query string
		if hsFilter.HostId != uuid.Nil {
			hostIdQueryString := fmt.Sprintf("%s.data -> 'Columns' -> 1 ->> 'Value' = '%s'", auditLogAbbrv, hsFilter.HostId.String())
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostIdQueryString)
		}

		//Build host name partial query string and add it to the additional options query string
		if hsFilter.HostName != "" {
			hostNameQueryString := fmt.Sprintf("%s.data -> 'Columns' -> 4 -> 'Value' -> 'host_info' ->> 'host_name' = '%s'", auditLogAbbrv, hsFilter.HostName)
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostNameQueryString)
		}

		//Build hardware uuid partial query string and add it to the additional options query string
		if hsFilter.HostHardwareId != uuid.Nil {
			hostHWUUIDQueryString := fmt.Sprintf("LOWER(%s.data -> 'Columns' -> 4 -> 'Value' -> 'host_info' ->> 'hardware_uuid') = '%s' ", auditLogAbbrv, strings.ToLower(hsFilter.HostHardwareId.String()))
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostHWUUIDQueryString)
		}
	}

	//Build host state partial query string and add it to the additional options query string
	if hsFilter.HostStatus != "" {
		hostStateQueryString := fmt.Sprintf("%s.data -> 'Columns' -> 2 -> 'Value' ->> 'host_state' = '%s'", auditLogAbbrv, strings.ToUpper(hsFilter.HostStatus))
		additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostStateQueryString)
	}

	//Build host status ID partial query string and add it to the additional options query string
	if hsFilter.Id != uuid.Nil {
		hostStatusIDQueryString := fmt.Sprintf("%s.entity_id = '%s'", auditLogAbbrv, hsFilter.Id.String())
		additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, hostStatusIDQueryString)
	}

	// Number of days and Date Filters are supposed to be mutually exclusive
	if hsFilter.NumberOfDays != 0 {
		// first parse numDays
		curTime := time.Now()
		hsFilter.FromDate = curTime.AddDate(0, 0, -hsFilter.NumberOfDays)
	}

	if !hsFilter.FromDate.IsZero() || !hsFilter.ToDate.IsZero() {
		// determine what dates params are set - try all combinations till one matches up
		if !hsFilter.FromDate.IsZero() && hsFilter.ToDate.IsZero() {
			fromDateQueryString := fmt.Sprintf("CAST(%s.created AS TIMESTAMP) >= CAST('%s' AS TIMESTAMP)", auditLogAbbrv, hsFilter.FromDate.Format(constants.ParamDateTimeFormatUTC))
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, fromDateQueryString)
		} else if hsFilter.FromDate.IsZero() && !hsFilter.ToDate.IsZero() {
			toDateQueryString := fmt.Sprintf("CAST(%s.created AS TIMESTAMP) <= CAST('%s' AS TIMESTAMP)", auditLogAbbrv, hsFilter.ToDate.Format(constants.ParamDateTimeFormatUTC))
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, toDateQueryString)
		} else if !hsFilter.FromDate.IsZero() && !hsFilter.ToDate.IsZero() {
			fromToDateQueryString := fmt.Sprintf("CAST(%s.created AS TIMESTAMP) >= CAST('%s' AS TIMESTAMP) AND CAST(%s.created AS TIMESTAMP) <= CAST('%s' AS TIMESTAMP) ", auditLogAbbrv, hsFilter.FromDate.Format(constants.ParamDateTimeFormatUTC), auditLogAbbrv, hsFilter.ToDate.Format(constants.ParamDateTimeFormatUTC))
			additionalOptionsQueryString = fmt.Sprintf("%s AND %s", additionalOptionsQueryString, fromToDateQueryString)
		}
	}

	if tableJoinString != "" {
		additionalOptionsQueryString = strings.Join([]string{tableJoinString, additionalOptionsQueryString}, " ")
	}

	if hsFilter.LatestPerHost {
		maxDateQueryString := fmt.Sprintf("INNER JOIN (SELECT entity_id, max(auj.created) AS max_date "+
			"FROM audit_log_entry auj %s GROUP BY entity_id) a "+
			"ON a.entity_id = au.entity_id "+
			"AND a.max_date = au.created", additionalOptionsQueryString)
		formattedQuery = fmt.Sprintf("%s %s", formattedQuery, maxDateQueryString)
	} else {
		formattedQuery = fmt.Sprintf("%s %s", formattedQuery, additionalOptionsQueryString)
	}

	// finalize query
	tx = tx.Raw(formattedQuery)
	if hsFilter.AfterId > 0 {
		tx = tx.Where("au.rowid > ?", hsFilter.AfterId)
	}
	tx = tx.Order("au.rowid asc")
	if hsFilter.Limit > 0 {
		tx = tx.Limit(hsFilter.Limit)
	}

	return tx
}

// buildLatestHostStatusSearchQuery is a helper function to build the query object for a hostStatus search
// with the LatestPerHost filter set to true
func buildLatestHostStatusSearchQuery(tx *gorm.DB, hsFilter *models.HostStatusFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/hoststatus_store:buildLatestHostStatusSearchQuery() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:buildLatestHostStatusSearchQuery() Leaving")

	tx = tx.Model(&hostStatus{})
	if tx == nil {
		return nil
	}

	// no criteria are specified
	if hsFilter == nil {
		defaultLog.Info("postgres/hoststatus_store:buildLatestHostStatusSearchQuery() No criteria specified in search query" +
			". Returning all rows.")
		return tx
	}

	// For validating HostName or HWUUID we join with the Host table
	if hsFilter.HostName != "" || hsFilter.HostHardwareId != uuid.Nil {
		tx = tx.Joins("INNER JOIN host h on h.id = host_id")
	}

	// Host Status ID
	if hsFilter.Id != uuid.Nil {
		tx = tx.Where("id = ?", hsFilter.Id.String())
	}

	// Host UUID
	if hsFilter.HostId != uuid.Nil {
		tx = tx.Where("host_id = ?", hsFilter.HostId.String())
	}

	// HWUUID
	if hsFilter.HostHardwareId != uuid.Nil {
		tx = tx.Where("h.hardware_uuid = ?", hsFilter.HostHardwareId.String())
	}

	// HostName
	if hsFilter.HostName != "" {
		tx = tx.Where("h.name = ?", hsFilter.HostName)
	}

	// Host Connection Status
	if hsFilter.HostStatus != "" {
		tx = tx.Where("status @> ?", fmt.Sprintf(`{"host_state": "%s"}`, strings.ToUpper(hsFilter.HostStatus)))
	}

	if hsFilter.AfterId > 0 {
		tx = tx.Where("rowid > ?", hsFilter.AfterId)
	}
	tx = tx.Order("rowid asc")
	if hsFilter.Limit > 0 {
		tx = tx.Limit(hsFilter.Limit)
	}

	return tx
}

func auditlogEntryToHostStatus(auRecord models.AuditLogEntry) (*hvs.HostStatus, error) {
	defaultLog.Trace("postgres/hoststatus_store:auditlogEntryToHostStatus() Entering")
	defer defaultLog.Trace("postgres/hoststatus_store:auditlogEntryToHostStatus() Leaving")

	var hostStatus hvs.HostStatus
	var err error

	if auRecord.EntityID != uuid.Nil {
		hostStatus.ID = auRecord.EntityID
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[1]) && auRecord.Data.Columns[1].Value != nil {
		hostStatus.HostID, err = uuid.Parse(fmt.Sprintf("%v", auRecord.Data.Columns[1].Value))
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - parsing hostid failed")
		}
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[2]) && auRecord.Data.Columns[2].Value != nil {
		c, err := json.Marshal(auRecord.Data.Columns[2].Value)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - marshalling HostStatusInformation failed")
		}
		err = json.Unmarshal(c, &hostStatus.HostStatusInformation)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - unmarshalling HostStatusInformation failed")
		}
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[3]) && auRecord.Data.Columns[3].Value != nil {
		c, err := json.Marshal(auRecord.Data.Columns[3].Value)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - marshalling HostManifest failed")
		}
		err = json.Unmarshal(c, &hostStatus.HostManifest)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - unmarshalling HostManifest failed")
		}
	}

	if !reflect.DeepEqual(models.AuditColumnData{}, auRecord.Data.Columns[4]) && auRecord.Data.Columns[4].Value != nil {
		createdString := fmt.Sprintf("%v", auRecord.Data.Columns[4].Value)
		hostStatus.Created, err = time.Parse(time.RFC3339Nano, createdString)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/hoststatus_store:auditlogEntryToHostStatus() - error parsing created timestamp")
		}
	}

	return &hostStatus, nil
}
