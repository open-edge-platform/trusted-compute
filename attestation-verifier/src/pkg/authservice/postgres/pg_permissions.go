/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type PostgresPermissionStore struct {
	db *gorm.DB
}

func (p *PostgresPermissionStore) Create(permission types.Permission) (*types.Permission, error) {
	defaultLog.Trace("permission Create")
	defer defaultLog.Trace("permission Create done")

	uuid, err := UUID()
	if err == nil {
		permission.ID = uuid
	} else {
		return &permission, errors.Wrap(err, "permission create: failed to get UUID")
	}
	if err := p.db.Create(&permission).Error; err != nil {
		return &permission, errors.Wrap(err, "permission create: failed")
	}
	return &permission, nil
}

func (p *PostgresPermissionStore) Retrieve(ps *types.PermissionSearch) (*types.Permission, error) {
	defaultLog.Trace("permission Retrieve")
	defer defaultLog.Trace("permission Retrieve done")

	tx := buildPermissionSearchQuery(p.db, ps)
	if tx == nil {
		return nil, errors.New("Unexpected Error. Could not build a gorm query object in Permissions RetrieveAll function.")
	}

	permission := &types.Permission{}
	if err := tx.First(permission).Error; err != nil {
		return nil, errors.Wrap(err, "permission retrieve: failed")
	}
	return permission, nil
}

// helper function to build the query object for a permission search.
func buildPermissionSearchQuery(tx *gorm.DB, ps *types.PermissionSearch) *gorm.DB {
	defaultLog.Trace("permission buildPermissionSearchQuery")
	defer defaultLog.Trace("permission buildPermissionSearchQuery done")

	if tx == nil {
		return nil
	}
	// check if we have a search criteria object. If we don't we have to build one so that we
	// are searching the correct table.
	if ps == nil {
		return tx.Where(&types.Permission{})
	}

	tx = tx.Where(&types.Permission{Rule: ps.Rule})

	if ps.Rule == "" && ps.RuleContains != "" {
		tx = tx.Where("rule like ? ", "%"+ps.RuleContains+"%")
	}
	if len(ps.IDFilter) > 0 {
		tx = tx.Where("id in (?) ", ps.IDFilter)
	}
	return tx
}

func (p *PostgresPermissionStore) RetrieveAll(ps *types.PermissionSearch) (types.Permissions, error) {
	defaultLog.Trace("permission RetrieveAll")
	defer defaultLog.Trace("permission RetrieveAll done")

	var permissions types.Permissions

	tx := buildPermissionSearchQuery(p.db, ps)
	if tx == nil {
		return permissions, errors.New("Unexpected Error. Could not build a gorm query object in Permissions RetrieveAll function.")
	}

	if err := tx.Find(&permissions).Error; err != nil {
		return permissions, errors.Wrap(err, "permission retrieve all: failed")
	}
	return permissions, nil
}

func (p *PostgresPermissionStore) Update(permission types.Permission) error {
	if err := p.db.Save(&permission).Error; err != nil {
		return errors.Wrap(err, "permission update: failed")
	}
	return nil
}

func (p *PostgresPermissionStore) Delete(permission types.Permission) error {
	if err := p.db.Delete(&permission).Error; err != nil {
		return errors.Wrap(err, "permission delete: failed")
	}
	return nil
}
