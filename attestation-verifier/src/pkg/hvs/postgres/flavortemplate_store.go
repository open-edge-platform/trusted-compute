/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

// FlavorTemplateStore to hold DB operations.
type FlavorTemplateStore struct {
	Store *DataStore
}

// NewFlavorTemplateStore to init FlavorTemplateStore.
func NewFlavorTemplateStore(store *DataStore) *FlavorTemplateStore {
	return &FlavorTemplateStore{Store: store}
}

// Create flavor template
func (ft *FlavorTemplateStore) Create(flvrTemplate *hvs.FlavorTemplate) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Create() Leaving")

	if flvrTemplate.ID == uuid.Nil {
		flavorTemplateID, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Create() Failed to generate flavor template ID")
		}

		flvrTemplate.ID = flavorTemplateID
	}

	createdTemplate := flavorTemplate{
		ID:      flvrTemplate.ID,
		Content: PGFlavorTemplateContent(*flvrTemplate),
		Deleted: false,
	}

	if err := ft.Store.Db.Create(&createdTemplate).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Create() Failed to create flavor")
	}
	return flvrTemplate, nil
}

// Retrieve flavor template
func (ft *FlavorTemplateStore) Retrieve(templateID uuid.UUID, includeDeleted bool) (*hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Retrieve() Leaving")

	sf := flavorTemplate{}
	row := ft.Store.Db.Model(flavorTemplate{}).Select("id,content,deleted").Where(&flavorTemplate{ID: templateID}).Row()
	if err := row.Scan(&sf.ID, &sf.Content, &sf.Deleted); err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.Error("postgres/flavortemplate_store:Retrieve() Failed to retrieve record from db", commErr.RowsNotFound)
			return nil, &commErr.StatusNotFoundError{Message: "Failed to retrieve record from db"}
		} else {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Retrieve() - Could not scan record")
		}
	}

	if includeDeleted || (!includeDeleted && !sf.Deleted) {
		flavorTemplate := hvs.FlavorTemplate{
			ID:          sf.ID,
			Label:       sf.Content.Label,
			Condition:   sf.Content.Condition,
			FlavorParts: sf.Content.FlavorParts,
		}
		return &flavorTemplate, nil
	}

	return nil, &commErr.StatusNotFoundError{Message: "FlavorTemplate with given ID is not found"}
}

// Search flavor template
func (ft *FlavorTemplateStore) Search(criteria *models.FlavorTemplateFilterCriteria) ([]hvs.FlavorTemplate, error) {
	defaultLog.Trace("postgres/flavortemplate_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Search() Leaving")

	tx := ft.buildFlavorTemplateSearchQuery(ft.Store.Db, criteria)
	if tx == nil {
		return nil, errors.New("postgres/flavortemplate_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("postgres/flavortemplate_store:Search() Error closing rows")
		}
	}()

	flavortemplates := []hvs.FlavorTemplate{}
	for rows.Next() {
		template := flavorTemplate{}

		if err := rows.Scan(&template.ID, &template.Content, &template.Deleted); err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:Search() - Could not scan record")
		}

		flavorTemplate := hvs.FlavorTemplate{
			ID:          template.ID,
			Label:       template.Content.Label,
			Condition:   template.Content.Condition,
			FlavorParts: template.Content.FlavorParts,
		}
		flavortemplates = append(flavortemplates, flavorTemplate)
	}

	return flavortemplates, nil
}

// Delete flavor template
func (ft *FlavorTemplateStore) Delete(templateID uuid.UUID) error {
	defaultLog.Trace("postgres/flavortemplate_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Delete() Leaving")

	_, err := ft.Retrieve(templateID, false)
	if err != nil {
		switch err.(type) {
		case *commErr.StatusNotFoundError:
			defaultLog.Error("postgres/flavortemplate_store:Delete() Flavor template with given ID does not exist or has been deleted")
			return err
		default:
			return errors.Wrap(err, "postgres/flavortemplate_store:Delete() Failed to retrieve FlavorTemplate with the given ID")
		}
	}

	err = ft.Store.Db.Model(flavorTemplate{}).Where(&flavorTemplate{ID: templateID}).Update(&flavorTemplate{Deleted: true}).Error
	if err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:Delete() - Could not Delete record "+templateID.String())
	}

	return nil
}

// Recover flavor template
func (ft *FlavorTemplateStore) Recover(recoverTemplates []string) error {
	defaultLog.Trace("postgres/flavortemplate_store:Recover() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:Recover() Leaving")

	ftc := models.FlavorTemplateFilterCriteria{IncludeDeleted: true}
	templates, err := ft.Search(&ftc)
	if err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:Recover() - Could not recover all records")
	}

	for _, template := range templates {
		for _, recover := range recoverTemplates {
			if strings.EqualFold(recover, template.Label) {
				defaultLog.Debug("postgres/flavortemplate_store:Recover() Recover default template ID ", template.ID)
				err := ft.Store.Db.Model(flavorTemplate{}).Update("deleted", false).Where(&flavorTemplate{ID: template.ID}).Error
				if err != nil {
					return errors.Wrap(err, "postgres/flavortemplate_store:Recover() - Could not recover record "+template.ID.String())
				}
			}
		}
	}

	return nil
}

func (ft *FlavorTemplateStore) buildFlavorTemplateSearchQuery(tx *gorm.DB, criteria *models.FlavorTemplateFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/flavortemplate_store:buildFlavorTemplateSearchQuery() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:buildFlavorTemplateSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&flavorTemplate{})
	if criteria == nil {
		return tx
	}

	if !criteria.IncludeDeleted {
		tx = tx.Where("deleted = ?", false)
	}

	if criteria.Ids != nil && len(criteria.Ids) > 0 {
		tx = tx.Where("id IN (?)", criteria.Ids)
	}
	if criteria.Label != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "label")+" = ?", criteria.Label)
	}
	if criteria.ConditionContains != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "condition")+" like ?", "%"+criteria.ConditionContains+"%")
	}
	if criteria.FlavorPartContains != "" {
		tx = tx.Where(convertToPgJsonqueryString("content", "flavor_parts")+" like ?", "%"+criteria.FlavorPartContains+"%")
	}

	return tx
}

func (ft *FlavorTemplateStore) AddFlavorgroups(ftId uuid.UUID, fgIds []uuid.UUID) error {
	defaultLog.Trace("postgres/flavortemplate_store:AddFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:AddFlavorgroups() Leaving")

	defaultLog.Debugf("postgres/flavortemplate_store:AddFlavorgroups() Linking flavor-template %v with flavorgroups %+q", ftId, fgIds)
	var hfgValues []string
	var hfgValueArgs []interface{}
	for _, fgId := range fgIds {
		hfgValues = append(hfgValues, "(?, ?)")
		hfgValueArgs = append(hfgValueArgs, ftId)
		hfgValueArgs = append(hfgValueArgs, fgId)
	}

	insertQuery := fmt.Sprintf("INSERT INTO flavortemplate_flavorgroup VALUES %s", strings.Join(hfgValues, ","))
	defaultLog.Debugf("postgres/flavortemplate_store:AddFlavorgroups() insert query - %v", insertQuery)
	err := ft.Store.Db.Model(flavortemplateFlavorgroup{}).Exec(insertQuery, hfgValueArgs...).Error
	if err != nil {
		return errors.Wrapf(err, "postgres/flavortemplate_store:AddFlavorgroups() failed to create flavor-template Flavorgroup associations  %v", insertQuery)
	}
	defaultLog.Debugf("postgres/flavortemplate_store:AddFlavorgroups() Linking flavor-template completed for %v ", ftId)
	return nil
}

func (ft *FlavorTemplateStore) RetrieveFlavorgroup(ftId uuid.UUID, fgId uuid.UUID) (*hvs.FlavorTemplateFlavorgroup, error) {
	defaultLog.Trace("postgres/flavortemplate_store:RetrieveFlavorgroup() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:RetrieveFlavorgroup() Leaving")

	ftfg := hvs.FlavorTemplateFlavorgroup{}
	row := ft.Store.Db.Model(&flavortemplateFlavorgroup{}).Where(&flavortemplateFlavorgroup{FlavortemplateId: ftId, FlavorgroupId: fgId}).Row()
	if err := row.Scan(&ftfg.FlavortemplateId, &ftfg.FlavorgroupId); err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:RetrieveFlavorgroup() failed to scan record")
	}
	return &ftfg, nil
}

func (ft *FlavorTemplateStore) RemoveFlavorgroups(ftId uuid.UUID, fgIds []uuid.UUID) error {
	defaultLog.Trace("postgres/flavortemplate_store:RemoveFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:RemoveFlavorgroups() Leaving")

	tx := ft.Store.Db
	if ftId != uuid.Nil {
		tx = tx.Where("flavortemplate_id = ?", ftId)
	}

	if len(fgIds) >= 1 {
		tx = tx.Where("flavorgroup_id IN (?)", fgIds)
	}

	if err := tx.Delete(&flavortemplateFlavorgroup{}).Error; err != nil {
		return errors.Wrap(err, "postgres/flavortemplate_store:RemoveFlavorgroups() failed to delete flavor-template Flavorgroup association")
	}
	return nil
}

func (hs *FlavorTemplateStore) SearchFlavorgroups(ftId uuid.UUID) ([]uuid.UUID, error) {
	defaultLog.Trace("postgres/flavortemplate_store:SearchFlavorgroups() Entering")
	defer defaultLog.Trace("postgres/flavortemplate_store:SearchFlavorgroups() Leaving")

	rows, err := hs.Store.Db.Model(&flavortemplateFlavorgroup{}).Select("flavorgroup_id").Where(&flavortemplateFlavorgroup{FlavortemplateId: ftId}).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavortemplate_store:SearchFlavorgroups() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	var fgIds []uuid.UUID
	for rows.Next() {
		var fgId uuid.UUID
		if err := rows.Scan(&fgId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavortemplate_store:SearchFlavorgroups() failed to scan record")
		}
		fgIds = append(fgIds, fgId)
	}
	return fgIds, nil
}
