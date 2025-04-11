/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresRoleStore struct {
	db *gorm.DB
}

// declared in pg_database.go
// var defaultLog = commLog.GetDefaultLogger()

func (r *PostgresRoleStore) Create(role types.Role) (*types.Role, error) {
	defaultLog.Trace("role Create")
	defer defaultLog.Trace("role Create done")

	uuid, err := UUID()
	if err == nil {
		role.ID = uuid
	} else {
		return &role, errors.Wrap(err, "role create: failed to get UUID")
	}
	if err := r.db.Create(&role).Error; err != nil {
		return &role, errors.Wrap(err, "role create: failed")
	}
	return &role, nil
}

func (r *PostgresRoleStore) Retrieve(rs *types.RoleSearch) (*types.Role, error) {
	defaultLog.Trace("role Retrieve")
	defer defaultLog.Trace("role Retrieve done")

	tx := buildRoleSearchQuery(r.db, rs)
	if tx == nil {
		return nil, errors.New("Unexpected Error. Could not build a gorm query object in Roles RetrieveAll function.")
	}

	role := &types.Role{}
	if err := tx.First(role).Error; err != nil {
		return nil, errors.Wrap(err, "role retrieve: failed")
	}
	return role, nil
}

// helper function to build the query object for a role search.
func buildRoleSearchQuery(tx *gorm.DB, rs *types.RoleSearch) *gorm.DB {
	defaultLog.Trace("role buildRoleSearchQuery")
	defer defaultLog.Trace("role buildRoleSearchQuery done")

	if tx == nil {
		return nil
	}
	// check if we have a search criteria object. If we don't we have to build one so that we
	// are searching the correct table.
	if rs == nil {
		return tx.Where(&types.Role{})
	}

	tx = tx.Where(&types.Role{RoleInfo: rs.RoleInfo})

	// Are we looking for roles that have values in the context field. If we only roles that does not have
	// context, then the `AllContext` field would be set to false.
	if rs.AllContexts == true {
		// We are looking for substring match. However, if the context field is non empty, this takes
		// precedence and the ContextContains is ignored.
		if rs.Context == "" && rs.ContextContains != "" {
			tx = tx.Where("context like ? ", "%"+rs.ContextContains+"%")
		}
	} else {
		// AllContexts is false - we only want records where the service and name match and the context
		// field is empty
		if rs.Context == "" {
			tx = tx.Where("context = ''")
		}
	}

	if len(rs.IDFilter) > 0 {
		tx = tx.Where("id in (?) ", rs.IDFilter)
	}
	if len(rs.ServiceFilter) > 0 {
		tx = tx.Where("service in (?) ", rs.ServiceFilter)
	}
	return tx
}

func (r *PostgresRoleStore) RetrieveAll(rs *types.RoleSearch) (types.Roles, error) {
	defaultLog.Trace("role RetrieveAll")
	defer defaultLog.Trace("role RetrieveAll done")

	var roles types.Roles

	tx := buildRoleSearchQuery(r.db, rs)
	if tx == nil {
		return roles, errors.New("Unexpected Error. Could not build a gorm query object in Roles RetrieveAll function.")
	}
	tx = tx.Preload("Permissions")
	if err := tx.Find(&roles).Error; err != nil {
		return roles, errors.Wrap(err, "role retrieve all: failed")
	}
	return roles, nil
}

func (r *PostgresRoleStore) Update(role types.Role) error {
	defaultLog.Trace("role Update")
	defer defaultLog.Trace("role Update done")

	if err := r.db.Save(&role).Error; err != nil {
		return errors.Wrap(err, "role update: failed")
	}
	return nil
}

func (r *PostgresRoleStore) Delete(role types.Role) error {
	defaultLog.Trace("Repository role Delete")
	defer defaultLog.Trace("Repository role Delete done")

	if err := r.db.Model(&role).Association("Users").Clear().Error; err != nil {
		return errors.Wrap(err, "Repository role delete: failed to clear user-role mapping")
	}

	if err := r.db.Delete(&role).Error; err != nil {
		return errors.Wrap(err, "role delete: failed")
	}
	return nil
}

func (r *PostgresPermissionStore) AddPermissions(role types.Role, permissions types.Permissions, mustAddAllPermissions bool) error {
	defaultLog.Trace("role AddPermisisons")
	defer defaultLog.Trace("role AddPermissions done")

	if err := r.db.Model(&role).Association("Permissions").Append(permissions).Error; err != nil {
		return errors.Wrap(err, "role add permissions: failed")
	}
	return nil
}

func (r *PostgresPermissionStore) DeletePermission(role types.Role, permissionID string) error {
	defaultLog.Trace("user DeletePermission")
	defer defaultLog.Trace("user DeletePermission done")

	var permission types.Permission
	tx := r.db.Where("id IN (?) ", permissionID)

	// lets sanitize the list with roles that already exists in the database.
	err := tx.Find(&permission).Error
	if err != nil {
		return errors.Wrapf(err, "role delete permissions: could not find permission id %s in database", permissionID)
	}
	if err = r.db.Model(&role).Association("Permissions").Delete(permission).Error; err != nil {
		return errors.Wrap(err, "role delete permission: failed")
	}
	return nil
}
