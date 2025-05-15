/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"encoding/json"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"

	"database/sql/driver"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/pkg/errors"
)

// Define all struct types here
type (
	PGJsonStrMap            map[string]interface{}
	PGFlavorMatchPolicies   hvs.FlavorMatchPolicies
	PGHostManifest          hvs.HostManifest
	PGHostStatusInformation hvs.HostStatusInformation
	PGFlavorContent         hvs.Flavor
	PGFlavorTemplateContent hvs.FlavorTemplate

	flavorGroup struct {
		ID                    uuid.UUID             `json:"id" gorm:"primary_key;type:uuid"`
		Name                  string                `json:"name" gorm:"type:varchar(255);not null;index:idx_flavorgroup_name"`
		FlavorTypeMatchPolicy PGFlavorMatchPolicies `json:"flavor_type_match_policy,omitempty" gorm:"type:jsonb"`
		Rowid                 int                   `json:"-" gorm:"auto_increment;not null"`
	}

	flavor struct {
		ID         uuid.UUID       `json:"id" gorm:"primary_key;type:uuid"`
		Content    PGFlavorContent `json:"flavor" gorm:"type:json"`
		CreatedAt  time.Time       `json:"created"`
		Label      string          `gorm:"unique;not null"`
		FlavorPart string          `json:"flavor_part"`
		Signature  string          `json:"signature"`
		Rowid      int             `json:"-" gorm:"auto_increment;not null"`
	}

	host struct {
		Id               uuid.UUID `gorm:"primary_key;type:uuid"`
		Name             string    `gorm:"unique;type:varchar(255);not null"`
		Description      string
		ConnectionString string        `gorm:"not null"`
		HardwareUuid     models.HwUUID `gorm:"type:uuid;index:idx_host_hardware_uuid"`
		Rowid            int           `gorm:"auto_increment;not null"`
	}

	hostFlavorgroup struct {
		HostId        uuid.UUID `gorm:"type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavorgroup_host"`
		FlavorgroupId uuid.UUID `gorm:"type:uuid REFERENCES flavor_group(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavorgroup_host"`
	}

	flavorgroupFlavor struct {
		FlavorgroupId uuid.UUID `gorm:"type:uuid REFERENCES flavor_group(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavor_flavorgroup"`
		FlavorId      uuid.UUID `gorm:"type:uuid REFERENCES flavor(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavor_flavorgroup"`
	}

	trustCache struct {
		FlavorId uuid.UUID `gorm:"type:uuid REFERENCES flavor(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavor_host"`
		HostId   uuid.UUID `gorm:"type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavor_host"`
	}

	hostuniqueFlavor struct {
		HostId   uuid.UUID `gorm:"type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_hostunique_flavor"`
		FlavorId uuid.UUID `gorm:"type:uuid REFERENCES flavor(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_hostunique_flavor"`
	}

	//FlavorTemplate - Table to store flavor templates
	flavorTemplate struct {
		ID      uuid.UUID               `gorm:"column:id;not null;primary_key;type:uuid"`
		Content PGFlavorTemplateContent `gorm:"column:content;type:json;not null"`
		Deleted bool                    `gorm:"column:deleted;not null;type:bool"`
	}

	flavortemplateFlavorgroup struct {
		FlavortemplateId uuid.UUID `gorm:"type:uuid REFERENCES flavor_template(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavorgroup_flavortemplate"`
		FlavorgroupId    uuid.UUID `gorm:"type:uuid REFERENCES flavor_group(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;uniqueIndex:idx_flavorgroup_flavortemplate"`
	}

	hostCredential struct {
		Id           uuid.UUID     `gorm:"primary_key;type:uuid"`
		HostId       uuid.UUID     `gorm:"type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;index:idx_host_credential_host_id"`
		HostName     string        `gorm:"type:varchar(255);index:idx_host_credential_hostname"`
		HardwareUuid models.HwUUID `gorm:"type:uuid;index:idx_host_credential_hardware_uuid"`
		Credential   string
		CreatedTs    time.Time
	}

	// hostStatus holds all the hostStatus records for VS-attested hosts
	hostStatus struct {
		ID         uuid.UUID               `gorm:"primary_key;type:uuid"`
		HostID     uuid.UUID               `sql:"type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;index:idx_host_status_host_id"`
		Status     PGHostStatusInformation `gorm:"column:status;type:jsonb"`
		HostReport PGHostManifest          `gorm:"column:host_report;type:jsonb"`
		CreatedAt  time.Time               `gorm:"column:created;not null"`
		Rowid      int                     `gorm:"auto_increment;not null"`
	}

	esxiCluster struct {
		Id               uuid.UUID `gorm:"primary_key;type:uuid"`
		ConnectionString string    `gorm:"column:connection_string;not null"`
		ClusterName      string    `gorm:"column:cluster_name;type:varchar(255);not null;index:idx_esxi_cluster_name"`
		Rowid            int       `gorm:"auto_increment;not null"`
	}

	esxiClusterHost struct {
		ClusterID uuid.UUID `gorm:"column:cluster_id;type:uuid REFERENCES esxi_cluster(id) ON UPDATE CASCADE ON DELETE CASCADE"`
		HostName  string    `gorm:"column:hostname;type:varchar(255) REFERENCES host(name) ON UPDATE CASCADE ON DELETE CASCADE"`
	}

	queue struct {
		Id        uuid.UUID         `json:"id,omitempty" gorm:"primary_key;unique;type:uuid"`
		Action    string            `json:"action"`
		Params    PGJsonStrMap      `json:"-" gorm:"type:json;default:'{}'"`
		CreatedAt time.Time         `json:"created"`
		UpdatedAt time.Time         `json:"updated"`
		State     models.QueueState `json:"state"`
		Message   string            `json:"message,omitempty"`
	}

	PGTrustReport hvs.TrustReport
	report        struct {
		ID          uuid.UUID     `gorm:"column:id;primary_key;"`
		HostID      uuid.UUID     `gorm:"column:host_id;type:uuid REFERENCES host(Id) ON UPDATE CASCADE ON DELETE CASCADE;not null;index:idx_report_host_id"`
		TrustReport PGTrustReport `gorm:"column:trust_report;not null;type:json"`
		Trusted     bool          `gorm:"column:trusted;not null"`
		CreatedAt   time.Time     `gorm:"column:created;not null"`
		Expiration  time.Time     `gorm:"column:expiration;not null"`
		Saml        string        `gorm:"column:saml;not null"`
		Rowid       int           `gorm:"auto_increment;not null"`
	}

	tpmEndorsement struct {
		ID                uuid.UUID `gorm:"primary_key;type:uuid"`
		HardwareUUID      uuid.UUID `gorm:"column:hardware_uuid;not null;type:uuid"`
		Issuer            string    `gorm:"column:issuer;not null"`
		Revoked           bool      `gorm:"column:revoked"`
		Certificate       string    `gorm:"column:certificate;not null"`
		Comment           string    `gorm:"column:comment"`
		CertificateDigest string    `gorm:"column:certificate_digest;not null"`
		Rowid             int       `gorm:"auto_increment;not null"`
	}

	//TODO add triggers
	PGAuditLogData models.AuditTableData
	auditLogEntry  struct {
		ID         uuid.UUID      `gorm:"primary_key;type:uuid"`
		EntityID   uuid.UUID      `gorm:"type:uuid"`
		EntityType string         `gorm:"type:varchar(255)"`
		CreatedAt  time.Time      `gorm:"column:created;not null"`
		Action     string         `gorm:"type:varchar(50)"`
		Data       PGAuditLogData `gorm:"type:jsonb"`
		Rowid      int            `gorm:"auto_increment;not null"`
	}

	tagCertificate struct {
		ID           uuid.UUID `gorm:"primary_key;type:uuid"`
		HardwareUUID uuid.UUID `gorm:"not null;type:uuid;column:hardware_uuid"`
		Certificate  []byte    `gorm:"not null;type:bytea"`
		Subject      string    `gorm:"not null"`
		Issuer       string    `gorm:"not null"`
		NotBefore    time.Time `gorm:"not null;column:notbefore"`
		NotAfter     time.Time `gorm:"not null;column:notafter"`
	}
)

func (qp PGJsonStrMap) Value() (driver.Value, error) {
	return json.Marshal(qp)
}

func (qp *PGJsonStrMap) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGJsonStrMap_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &qp)
}

func (phm PGHostManifest) Value() (driver.Value, error) {
	return json.Marshal(phm)
}

func (phm *PGHostManifest) Scan(value interface{}) error {
	// no trace comments here as it is a high frequency function.
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGHostManifest_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &phm)
}

func (hm PGHostStatusInformation) Value() (driver.Value, error) {
	return json.Marshal(hm)
}

func (hm *PGHostStatusInformation) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGHostStatusInformation_Scan() - type assertion to []byte failed")
	}

	return json.Unmarshal(b, &hm)
}

func (fmp PGFlavorMatchPolicies) Value() (driver.Value, error) {
	return json.Marshal(fmp)
}

func (fmp *PGFlavorMatchPolicies) Scan(value interface{}) error {
	var b []byte

	switch v := value.(type) {
	case []byte:
		b = v
	case string:
		b = []byte(v)
	default:
		return errors.New("postgres/models:PGFlavorMatchPolicies_Scan() - type assertion and/or conversion to []byte failed.")
	}

	return json.Unmarshal(b, &fmp)
}

func (trp PGTrustReport) Value() (driver.Value, error) {
	return json.Marshal(trp)
}

func (trp *PGTrustReport) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGTrustReport_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &trp)
}

func (alp PGAuditLogData) Value() (driver.Value, error) {
	return json.Marshal(alp)
}

func (alp *PGAuditLogData) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGAuditLogData_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &alp)
}

func (fl PGFlavorContent) Value() (driver.Value, error) {
	return json.Marshal(fl)
}

func (fl *PGFlavorContent) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGFlavorContent_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fl)
}

func (fl PGFlavorTemplateContent) Value() (driver.Value, error) {
	return json.Marshal(fl)
}

func (fl *PGFlavorTemplateContent) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return errors.New("postgres/models:PGFlavorTemplateContent_Scan() - type assertion to []byte failed")
	}
	return json.Unmarshal(b, &fl)
}
