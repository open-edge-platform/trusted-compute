/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type PostgresUserStore struct {
	db *gorm.DB
}

func (r *PostgresUserStore) Create(u types.User) (*types.User, error) {
	defaultLog.Trace("user Create")
	defer defaultLog.Trace("user Create done")

	uuid, err := UUID()
	if err == nil {
		u.ID = uuid
	} else {
		return &u, errors.Wrap(err, "user create: failed to get UUID")
	}
	err = r.db.Create(&u).Error
	if err != nil {
		return &u, errors.Wrap(err, "user create: failed")
	}
	return &u, nil
}

func (r *PostgresUserStore) Retrieve(u types.User) (*types.User, error) {
	defaultLog.Trace("user Retrieve")
	defer defaultLog.Trace("user Retrieve done")

	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, errors.Wrap(err, "user retrieve: failed")
	}
	return &u, nil
}

func (r *PostgresUserStore) RetrieveAll(u types.User) (types.Users, error) {
	defaultLog.Trace("user RetrieveAll")
	defer defaultLog.Trace("user RetrieveAll done")

	var users types.Users
	err := r.db.Where(&u).Find(&users).Error
	if err != nil {
		return nil, errors.Wrap(err, "user retrieve: failed")
	}

	return users, nil
}

func (r *PostgresUserStore) Update(u types.User) error {
	err := r.db.Save(&u).Error
	if err != nil {
		return errors.Wrap(err, "user update: failed")
	}
	return nil
}

func (r *PostgresUserStore) Delete(u types.User) error {
	defaultLog.Trace("user Delete")
	defer defaultLog.Trace("user Delete done")
	if err := r.db.Model(&u).Association("Roles").Clear().Error; err != nil {
		return errors.Wrap(errors.New(err()), "user delete: failed to clear user-role mapping")
	}
	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "user delete: failed to clear user-role mapping")
	}
	return nil
}

func (r *PostgresUserStore) GetRoles(u types.User, rs *types.RoleSearch, includeID bool) (userRoles []types.Role, err error) {
	defaultLog.Trace("user GetRoles")
	defer defaultLog.Trace("user GetRoles done")

	var cols string

	if includeID {
		cols = "roles.id, "
	}
	cols = cols + "roles.service, roles.name, roles.context"
	tx := r.db.Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on user_roles.user_id = users.id").Where(&u)

	if rs != nil {
		tx = buildRoleSearchQuery(tx, rs)
	}
	tx = tx.Select(cols)

	if err := tx.Find(&userRoles).Error; err != nil {
		return userRoles, errors.Wrap(err, "user delete: failed to clear user-role mapping")
	}
	return userRoles, nil
}

// TODO - use RoleSearch to filter by services and IDs and context. This function should only be used by JWT token
// for now

func (r *PostgresUserStore) GetPermissions(u types.User, rs *types.RoleSearch) (userPerms []ct.PermissionInfo, err error) {
	defaultLog.Trace("user GetPermissions")
	defer defaultLog.Trace("user GetPermissions done")

	type Result struct {
		Service string
		Context string
		Rule    string
	}

	var res = []Result{}

	query := r.db.Table("users u").
		Select("DISTINCT r.service as service, r.context as context, p.rule as rule").
		Joins("INNER JOIN user_roles ur ON u.id = ur.user_id").
		Joins("INNER JOIN roles r ON ur.role_id = r.id").
		Joins("INNER JOIN role_permissions rp ON r.id = rp.role_id").
		Joins("INNER JOIN permissions p ON rp.permission_id = p.id")

	if u.Name != "" {
		query = query.Where("u.name = ?", u.Name)
	} else if u.ID != "" {
		query = query.Where("u.id = ?", u.ID)
	}

	query = query.Order("service, context")

	// Execute the query
	if err := query.Scan(&res).Error; err != nil {
		return nil, err
	}

	if len(res) == 0 {
		return nil, nil
	}

	curr := ct.PermissionInfo{Service: res[0].Service, Context: res[0].Context, Rules: []string{res[0].Rule}}
	defaultLog.Info("First record:", res[0])
	for i := 1; i < len(res); i++ {
		defaultLog.Info("Record ", i, ":", res[i])
		if res[i].Service == curr.Service && res[i].Context == curr.Context {
			curr.Rules = append(curr.Rules, res[i].Rule)
		} else {
			userPerms = append(userPerms, curr)
			curr = ct.PermissionInfo{Service: res[i].Service, Context: res[i].Context, Rules: []string{res[i].Rule}}
		}
	}
	userPerms = append(userPerms, curr)

	return userPerms, nil
}

func (r *PostgresUserStore) AddRoles(u types.User, roles types.Roles, mustAddAllRoles bool) error {
	defaultLog.Trace("user AddRoles")
	defer defaultLog.Trace("user AddRoles done")

	if err := r.db.Model(&u).Association("Roles").Append(roles).Error; err != nil {
		return errors.Wrap(errors.New(err()), "user add roles: failed")
	}
	return nil
}

func (r *PostgresUserStore) GetUserRoleByID(u types.User, roleID string) (types.Role, error) {
	defaultLog.Trace("user GetRole")
	defer defaultLog.Trace("user GetRole done")
	var userRole types.Role

	tx := r.db.Joins("INNER JOIN user_roles on user_roles.role_id = roles.id INNER JOIN users on "+
		"user_roles.user_id = users.id").Where("users.id = ?", u.ID).Where("roles.id = ?", roleID)
	err := tx.Find(&userRole).Error
	if err != nil {
		return userRole, errors.Wrapf(err, "user get role: could not find role id %s associated to user", roleID)
	}
	return userRole, nil
}

func (r *PostgresUserStore) DeleteRole(u types.User, roleID string, svcFltr []string) error {
	defaultLog.Trace("user DeleteRole")
	defer defaultLog.Trace("user DeleteRole done")

	var role types.Role
	tx := r.db.Where("id IN (?) ", roleID)
	if len(svcFltr) > 0 {
		tx = tx.Where("service in (?) ", svcFltr)
	}

	// lets sanitize the list with roles that already exists in the database.
	err := tx.Find(&role).Error
	if err != nil {
		return errors.Wrapf(err, "user delete roles: could not find role id %s in database", roleID)
	}
	if err = r.db.Model(&u).Association("Roles").Delete(role); err != nil {
		return errors.Wrap(err, "user delete role: failed")
	}
	return nil
}
