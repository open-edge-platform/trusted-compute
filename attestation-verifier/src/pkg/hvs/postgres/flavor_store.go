/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type FlavorStore struct {
	Store *DataStore
}

func NewFlavorStore(store *DataStore) *FlavorStore {
	return &FlavorStore{store}
}

// create flavors
func (f *FlavorStore) Create(signedFlavor *hvs.SignedFlavor) (*hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Create() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Create() Leaving")
	if signedFlavor == nil || signedFlavor.Signature == "" || signedFlavor.Flavor.Meta.Description[hvs.Label].(string) == "" {
		return nil, errors.New("postgres/flavor_store:Create()- invalid input : must have content, signature and the label for the flavor")
	}

	if signedFlavor.Flavor.Meta.ID == uuid.Nil {
		newUuid, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/flavor_store:Create() failed to create new UUID")
		}
		signedFlavor.Flavor.Meta.ID = newUuid
	}

	dbf := flavor{
		ID:         signedFlavor.Flavor.Meta.ID,
		Content:    PGFlavorContent(signedFlavor.Flavor),
		CreatedAt:  time.Now(),
		Label:      signedFlavor.Flavor.Meta.Description[hvs.Label].(string),
		FlavorPart: signedFlavor.Flavor.Meta.Description[hvs.FlavorPartDescription].(string),
		Signature:  signedFlavor.Signature,
	}

	if err := f.Store.Db.Create(&dbf).Error; err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Create() failed to create flavor")
	}
	return signedFlavor, nil
}

func (f *FlavorStore) Search(flavorFilter *models.FlavorVerificationFC) ([]hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Search() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Search() Leaving")

	var tx *gorm.DB
	var err error

	tx = f.Store.Db.Table("flavor f").Select("f.id, f.content, f.signature, f.rowid")
	// build partial query with all the given flavor Id's
	if len(flavorFilter.FlavorFC.Ids) > 0 {
		var flavorIds []string
		for _, fId := range flavorFilter.FlavorFC.Ids {
			flavorIds = append(flavorIds, fId.String())
		}
		tx = tx.Where("f.id IN (?)", flavorFilter.FlavorFC.Ids)
	}
	// build partial query with the given key-value pair from flavor description
	if flavorFilter.FlavorFC.Key != "" && flavorFilter.FlavorFC.Value != "" {
		tx = tx.Where(convertToPgJsonqueryString("f.content", "meta.description."+flavorFilter.FlavorFC.Key)+" = ?", flavorFilter.FlavorFC.Value)
	}
	if flavorFilter.FlavorFC.FlavorgroupID.String() != "" ||
		len(flavorFilter.FlavorFC.FlavorParts) >= 1 || len(flavorFilter.FlavorPartsWithLatest) >= 1 || flavorFilter.FlavorMeta != nil || len(flavorFilter.FlavorMeta) >= 1 {
		if len(flavorFilter.FlavorFC.FlavorParts) >= 1 {
			flavorFilter.FlavorPartsWithLatest = getFlavorPartsWithLatestMap(flavorFilter.FlavorFC.FlavorParts, flavorFilter.FlavorPartsWithLatest)
		}
		// add all flavor parts in list of flavor Parts
		tx = f.buildMultipleFlavorPartQueryString(tx, flavorFilter.FlavorFC.FlavorgroupID, flavorFilter.FlavorMeta, flavorFilter.FlavorPartsWithLatest)
	}

	if tx == nil {
		return nil, errors.New("postgres/flavor_store:Search() Unexpected Error. Could not build gorm query" +
			" object in flavor Search function")
	}

	if flavorFilter.FlavorFC.AfterId > 0 {
		tx = tx.Where("f.rowid > ?", flavorFilter.FlavorFC.AfterId)
	}
	tx = tx.Order("f.rowid asc")
	if flavorFilter.FlavorFC.Limit > 0 {
		tx = tx.Limit(flavorFilter.FlavorFC.Limit)
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	signedFlavors := []hvs.SignedFlavor{}

	for rows.Next() {
		sf := hvs.SignedFlavor{}
		if err := rows.Scan(&sf.Flavor.Meta.ID, (*PGFlavorContent)(&sf.Flavor), &sf.Signature, &sf.RowId); err != nil {
			return nil, errors.Wrap(err, "postgres/flavor_store:Search() failed to scan record")
		}
		signedFlavors = append(signedFlavors, sf)
	}
	return signedFlavors, nil
}

func (f *FlavorStore) buildMultipleFlavorPartQueryString(tx *gorm.DB, fgId uuid.UUID, flavorMetaInfo map[hvs.FlavorPartName][]models.FlavorMetaKv, flavorPartsWithLatest map[hvs.FlavorPartName]bool) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildMultipleFlavorPartQueryString() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildMultipleFlavorPartQueryString() Leaving")

	var biosQuery *gorm.DB
	var osQuery *gorm.DB
	var aTagQuery *gorm.DB
	var softwareQuery *gorm.DB
	var hostUniqueQuery *gorm.DB
	var imaQuery *gorm.DB

	if flavorPartsWithLatest != nil && len(flavorPartsWithLatest) >= 1 {
		for flavorPart := range flavorPartsWithLatest {
			switch flavorPart {
			case hvs.FlavorPartPlatform:
				biosQuery = f.Store.Db
				biosQuery = buildFlavorPartQueryStringWithFlavorParts(hvs.FlavorPartPlatform.String(), fgId.String(), biosQuery)
				// build biosQuery with all the platform flavor query attributes from host manifest
				pfQueryAttributes := flavorMetaInfo[hvs.FlavorPartPlatform]
				for _, pfQueryAttribute := range pfQueryAttributes {
					biosQuery = biosQuery.Where(convertToPgJsonqueryString("f.content", pfQueryAttribute.Key)+" = ?", pfQueryAttribute.Value)
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartPlatform] {
					biosQuery = biosQuery.Order("f.created_at desc").Limit(1)
				}

			case hvs.FlavorPartOs:
				osQuery = f.Store.Db
				osQuery = buildFlavorPartQueryStringWithFlavorParts(hvs.FlavorPartOs.String(), fgId.String(), osQuery)
				// build osQuery with all the OS flavor query attributes from host manifest
				osfQueryAttributes := flavorMetaInfo[hvs.FlavorPartOs]
				for _, osfQueryAttribute := range osfQueryAttributes {
					osQuery = osQuery.Where(convertToPgJsonqueryString("f.content", osfQueryAttribute.Key)+" = ?", osfQueryAttribute.Value)
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartOs] {
					osQuery = osQuery.Order("f.created_at desc").Limit(1)
				}

			case hvs.FlavorPartHostUnique:
				hostUniqueQuery = f.Store.Db
				hostUniqueQuery = hostUniqueQuery.Table("flavor f")
				hostUniqueQuery = hostUniqueQuery.Select("f.id")
				hostUniqueQuery = hostUniqueQuery.Where(convertToPgJsonqueryString("f.content", "meta.description.flavor_part")+" = ?", hvs.FlavorPartHostUnique.String())
				// build host unique Query with all the host unique flavor query attributes from host manifest
				hufQueryAttributes := flavorMetaInfo[hvs.FlavorPartHostUnique]
				for _, hufQueryAttribute := range hufQueryAttributes {
					hostUniqueQuery = hostUniqueQuery.Where(convertToPgJsonqueryString("f.content", hufQueryAttribute.Key)+" = ?", hufQueryAttribute.Value)
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartHostUnique] {
					hostUniqueQuery = hostUniqueQuery.Order("f.created_at desc").Limit(1)
				}

			case hvs.FlavorPartSoftware:
				softwareQuery = f.Store.Db
				softwareQuery = buildFlavorPartQueryStringWithFlavorParts(hvs.FlavorPartSoftware.String(), fgId.String(), softwareQuery)
				sfQueryAttributes := flavorMetaInfo[hvs.FlavorPartSoftware]
				// build software Query with all the software flavor query attributes from host manifest
				for _, sfQueryAttribute := range sfQueryAttributes {
					softwareQuery = softwareQuery.Where("f.label IN (?)", sfQueryAttribute.Value.([]string))
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartSoftware] {
					softwareQuery = softwareQuery.Order("f.created_at desc").Limit(1)
				}

			case hvs.FlavorPartAssetTag:
				aTagQuery = f.Store.Db
				aTagQuery = aTagQuery.Table("flavor f").Select("f.id")
				aTagQuery = aTagQuery.Where(convertToPgJsonqueryString("f.content", "meta.description.flavor_part")+" = ?", hvs.FlavorPartAssetTag)
				// build assetTag Query with all the assetTag flavor query attributes from host manifest
				atfQueryAttributes := flavorMetaInfo[hvs.FlavorPartAssetTag]
				for _, atfQueryAttribute := range atfQueryAttributes {
					aTagQuery = aTagQuery.Where(convertToPgJsonqueryString("f.content", atfQueryAttribute.Key)+" = ?", atfQueryAttribute.Value)
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartAssetTag] {
					aTagQuery = aTagQuery.Order("f.created_at desc").Limit(1)
				}

			case hvs.FlavorPartIma:
				imaQuery = f.Store.Db
				imaQuery = buildFlavorPartQueryStringWithFlavorParts(hvs.FlavorPartIma.String(), fgId.String(), imaQuery)
				// build biosQuery with all the ima flavor query attributes from host manifest
				imaFlavorQueryAttributes := flavorMetaInfo[hvs.FlavorPartIma]
				for _, imaFlavorQueryAttribute := range imaFlavorQueryAttributes {
					imaQuery = imaQuery.Where(convertToPgJsonqueryString("f.content", imaFlavorQueryAttribute.Key)+" = ?", imaFlavorQueryAttribute.Value)
				}
				// apply limit if latest
				if flavorPartsWithLatest[hvs.FlavorPartIma] {
					imaQuery = imaQuery.Order("f.created_at desc").Limit(1)
				}

			default:
				defaultLog.Error("postgres/flavor_store:buildMultipleFlavorPartQueryString() Invalid flavor part")
				return nil
			}
		}
	}

	subQuery := tx
	// add bios query to sub query
	if biosQuery != nil {
		biosSubQuery := biosQuery.SubQuery()
		subQuery = subQuery.Where("f.id IN ?", biosSubQuery)
	}
	// add OS query string to sub query
	if osQuery != nil {
		osSubQuery := osQuery.SubQuery()
		if biosQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", osSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", osSubQuery)
		}
	}
	// add software query to sub query
	if softwareQuery != nil {
		softwareSubQuery := softwareQuery.SubQuery()
		if biosQuery != nil || osQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", softwareSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", softwareSubQuery)
		}
	}
	// add asset tag query to sub query
	if aTagQuery != nil {
		aTagSubQuery := aTagQuery.SubQuery()
		if biosQuery != nil || osQuery != nil || softwareQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", aTagSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", aTagSubQuery)
		}
	}
	// add host-unique query to sub query
	if hostUniqueQuery != nil {
		hostUniqueSubQuery := hostUniqueQuery.SubQuery()
		if biosQuery != nil || osQuery != nil || softwareQuery != nil || aTagQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", hostUniqueSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", hostUniqueSubQuery)
		}
	}

	// add ima query to sub query
	if imaQuery != nil {
		imaSubQuery := imaQuery.SubQuery()
		if biosQuery != nil || osQuery != nil || softwareQuery != nil || aTagQuery != nil || hostUniqueQuery != nil {
			subQuery = subQuery.Or("f.id IN ?", imaSubQuery)
		} else {
			subQuery = subQuery.Where("f.id IN ?", imaSubQuery)
		}
	}

	// check if none of the flavor part queries are not formed,
	if subQuery != nil && (biosQuery != nil || aTagQuery != nil || softwareQuery != nil || hostUniqueQuery != nil || osQuery != nil || imaQuery != nil) {
		tx = subQuery
	} else if fgId != uuid.Nil {
		fgSubQuery := buildFlavorPartQueryStringWithFlavorgroup(fgId.String(), tx).SubQuery()
		tx = tx.Where("f.id IN ?", fgSubQuery)
	}
	return tx
}

func convertToPgJsonqueryString(queryHead string, jsonKeyPath string) string {
	jsonQueryStr := queryHead
	flavorMetaPath := strings.Split(jsonKeyPath, ".")
	for i := 0; i < len(flavorMetaPath)-1; i++ {
		jsonQueryStr = fmt.Sprintf("%s -> '%s'", jsonQueryStr, flavorMetaPath[i])
	}
	jsonQueryStr = fmt.Sprintf("%s ->> '%s'", jsonQueryStr, flavorMetaPath[len(flavorMetaPath)-1])
	return jsonQueryStr
}

func buildFlavorPartQueryStringWithFlavorParts(flavorpart, flavorgroupId string, tx *gorm.DB) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorParts() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorParts() Leaving")

	var flavorgroupUuid uuid.UUID
	if flavorgroupId != "" {
		fgUuid, err := uuid.Parse(flavorgroupId)
		if err != nil {
			defaultLog.WithError(err).Error("Failed to parse flavor group ID")
		}
		flavorgroupUuid = fgUuid
	}
	if flavorgroupUuid != uuid.Nil {
		subQuery := buildFlavorPartQueryStringWithFlavorgroup(flavorgroupId, tx)
		tx = subQuery.Where(convertToPgJsonqueryString("f.content", "meta.description.flavor_part")+" = ?", flavorpart)
	} else {
		tx = tx.Table("flavor f").Select("f.id").Joins("INNER JOIN flavorgroup_flavor fgf ON f.id = fgf.flavor_id")
		tx = tx.Joins("INNER JOIN flavor_group fg ON fgf.flavorgroup_id = fg.id")
		tx = tx.Where(convertToPgJsonqueryString("f.content", "meta.description.flavor_part")+" = ?", flavorpart)
	}
	return tx
}

func buildFlavorPartQueryStringWithFlavorgroup(flavorgroupId string, tx *gorm.DB) *gorm.DB {
	defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorgroup() Entering")
	defer defaultLog.Trace("postgres/flavor_store:buildFlavorPartQueryStringWithFlavorgroup() Leaving")

	tx = tx.Table("flavor f").Select("f.id").Joins("INNER JOIN flavorgroup_flavor fgf ON f.id = fgf.flavor_id")
	tx = tx.Joins("INNER JOIN flavor_group fg ON fgf.flavorgroup_id = fg.id")
	tx = tx.Where("fg.id = ?", flavorgroupId)
	return tx
}

// helper function used to add the list of flavor parts in the map[flavorPart]bool, indicating if latest flavor is required
func getFlavorPartsWithLatestMap(flavorParts []hvs.FlavorPartName, flavorPartsWithLatestMap map[hvs.FlavorPartName]bool) map[hvs.FlavorPartName]bool {
	if len(flavorParts) <= 0 {
		return flavorPartsWithLatestMap
	}
	if len(flavorPartsWithLatestMap) <= 0 {
		flavorPartsWithLatestMap = make(map[hvs.FlavorPartName]bool)
	}
	for _, flavorPart := range flavorParts {
		if _, ok := flavorPartsWithLatestMap[flavorPart]; !ok {
			flavorPartsWithLatestMap[flavorPart] = false
		}
	}

	return flavorPartsWithLatestMap
}

// retrieve flavors
func (f *FlavorStore) Retrieve(flavorId uuid.UUID) (*hvs.SignedFlavor, error) {
	defaultLog.Trace("postgres/flavor_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Retrieve() Leaving")

	sf := hvs.SignedFlavor{}
	row := f.Store.Db.Model(flavor{}).Select("content, signature").Where(&flavor{ID: flavorId}).Row()
	if err := row.Scan((*PGFlavorContent)(&sf.Flavor), &sf.Signature); err != nil {
		return nil, errors.Wrap(err, "postgres/flavor_store:Retrieve() - Could not scan record ")
	}
	return &sf, nil
}

// delete flavors
func (f *FlavorStore) Delete(flavorId uuid.UUID) error {
	defaultLog.Trace("postgres/flavor_store:Delete() Entering")
	defer defaultLog.Trace("postgres/flavor_store:Delete() Leaving")

	dbFlavor := flavor{
		ID: flavorId,
	}
	if err := f.Store.Db.Where(&dbFlavor).Delete(&dbFlavor).Error; err != nil {
		return errors.Wrap(err, "postgres/flavor_store:Delete() failed to delete Flavor")
	}
	return nil
}
