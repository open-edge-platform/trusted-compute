/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"errors"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/postgres"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	ct "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"golang.org/x/crypto/bcrypt"
)

func createPermission(db domain.AASDatabase, rule string) (*types.Permission, error) {
	defaultLog.Trace("entering tasks/createPermission")
	defer defaultLog.Trace("leaving tasks/createPermission")

	permission, err := db.PermissionStore().Retrieve(&types.PermissionSearch{
		Rule: rule,
	})
	if err != nil {
		uuid, err := postgres.UUID()
		if err != nil {
			return nil, err
		}
		permission, err = db.PermissionStore().Create(types.Permission{ID: uuid, Rule: rule})
	}
	return permission, err
}

func createRole(db domain.AASDatabase, roleCreate ct.RoleCreate) (*types.Role, error) {
	defaultLog.Trace("entering tasks/createRole")
	defer defaultLog.Trace("leaving tasks/createRole")

	var role *types.Role

	newRole := types.Role{RoleInfo: roleCreate.RoleInfo}
	role, err := db.RoleStore().Retrieve(&types.RoleSearch{
		RoleInfo:    ct.RoleInfo{Name: newRole.Name, Service: newRole.Service, Context: newRole.Context},
		AllContexts: false,
	})

	if err != nil {
		for _, rule := range roleCreate.Permissions {
			newPermRule := &types.PermissionSearch{Rule: rule}
			if existPerm, err := db.PermissionStore().Retrieve(newPermRule); err == nil {
				newRole.Permissions = append(newRole.Permissions, *existPerm)
				continue
			} else {
				if newPerm, err := db.PermissionStore().Create(types.Permission{Rule: rule}); err == nil {
					newRole.Permissions = append(newRole.Permissions, *newPerm)
				}
			}
		}

		newRole.ID, _ = postgres.UUID()
		role, err = db.RoleStore().Create(newRole)
	}

	return role, err
}

func addDBUser(db domain.AASDatabase, username string, password string, roles []types.Role) error {

	defaultLog.Trace("entering tasks/addDBUser")
	defer defaultLog.Trace("leaving tasks/addDBUser")

	if username == "" {
		return errors.New("db user setup: Username cannot be empty")
	}
	if password == "" {
		return errors.New("db user setup: Password cannot be empty")
	}
	validErr := validation.ValidateUserNameString(username)
	if validErr != nil {
		return validErr
	}
	validErr = validation.ValidatePasswordString(password)
	if validErr != nil {
		return validErr
	}

	userInDB, err := db.UserStore().Retrieve(types.User{Name: username})
	userExist := err == nil
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("failed to generate hash from password")
		return err
	}

	var uuid string
	if userExist && userInDB != nil {
		uuid = userInDB.ID
		err = db.UserStore().Update(types.User{ID: uuid, Name: username, PasswordHash: hash, PasswordCost: bcrypt.DefaultCost, Roles: roles})
	} else {
		_, err = db.UserStore().Create(types.User{Name: username, PasswordHash: hash, PasswordCost: bcrypt.DefaultCost, Roles: roles})
	}

	if err != nil {
		defaultLog.WithError(err).Error("failed to create or update register host user in db")
		return err
	}
	return nil
}
