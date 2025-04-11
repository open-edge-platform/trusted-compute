/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	aasModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

	"github.com/gorilla/mux"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

type RolesController struct {
	Database domain.AASDatabase
}

func (controller RolesController) CreateRole(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to createRole")
	defer defaultLog.Trace("createRole return")

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	// authorize rest api endpoint based on token
	ctxMap, err := authorizeEndpoint(r, []string{consts.RoleCreate}, true)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var rc aasModel.RoleCreate
	err = dec.Decode(&rc)
	if err != nil {
		secLog.Warningf("%s: Unauthorized create role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	rl := types.Role{RoleInfo: rc.RoleInfo}

	// we have the role now. If ctxMap is not nil, we need to make sure that the right privilege is
	// available to create a role with the requested service
	if ctxMap != nil {
		if _, ok := (*ctxMap)[rl.Service]; !ok {
			errMsg := fmt.Sprintf("%s: not allowed to create role as service: %s", commLogMsg.UnauthorizedAccess, rl.Service)
			secLog.Error(errMsg)
			return nil, http.StatusForbidden, &commErr.PrivilegeError{Message: errMsg}
		}
	}

	// at this point, we should have privilege to create the requested role. So, lets proceed

	validationErr := ValidateRoleString(rl.Name)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = ValidateServiceString(rl.Service)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = ValidateContextString(rl.Context)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = ValidatePermissions(rc.Permissions)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	// at this point, we should have privilege to create the requested role. So, lets proceed

	existingRole, err := controller.Database.RoleStore().Retrieve(&types.RoleSearch{
		RoleInfo:    aasModel.RoleInfo{Service: rl.Service, Name: rl.Name, Context: rl.Context},
		AllContexts: false,
	})

	if existingRole != nil {
		secLog.WithField("role", rl).Warningf("%s: Trying to create duplicated role from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "same role exists"}
	}

	// Create the role

	// first check if we have permissions. If there are permissions, we need to to add this to the Permissions
	// table. Given a list of permissions, lets get the ids of the ones that exist in the database, for the
	// ones that does not exist, create them in the database.

	// lets get ID of each permission from the database. if it does not exist create them and add it
	for _, rule := range rc.Permissions {
		newPermRule := &types.PermissionSearch{Rule: rule}
		if existPerm, err := controller.Database.PermissionStore().Retrieve(newPermRule); err == nil {
			rl.Permissions = append(rl.Permissions, *existPerm)
			continue
		} else {
			if newPerm, err := controller.Database.PermissionStore().Create(types.Permission{Rule: rule}); err == nil {
				rl.Permissions = append(rl.Permissions, *newPerm)
			} else {
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "same role exists"}
			}
		}

	}

	created, err := controller.Database.RoleStore().Create(rl)
	if err != nil {
		defaultLog.WithError(err).Error("Error creating new role")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error creating new role"}
	}
	secLog.WithField("role", rl).Infof("%s: Role created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	roleBytes, err := json.Marshal(created)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	return string(roleBytes), http.StatusCreated, nil
}

func (controller RolesController) GetRole(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to getRole")
	defer defaultLog.Trace("getRole return")

	// authorize rest api endpoint based on token
	ctxMap, err := authorizeEndpoint(r, []string{consts.RoleRetrieve}, true)
	if err != nil {
		secLog.Warningf("%s: Unauthorized get role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	// at this point, we should get the role and later check if user has permission to read this role.
	// this is not as efficient. It retrieves a record from the database even though the user does
	// not have privilege to read the record.
	rl, err := controller.Database.RoleStore().Retrieve(&types.RoleSearch{AllContexts: true, IDFilter: []string{id}})

	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve role")
		return nil, http.StatusNotFound, nil
	}

	// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
	// a role in the token that can read this role
	if ctxMap != nil {
		if _, ok := (*ctxMap)[rl.Service]; !ok {
			errMsg := fmt.Sprintf("%s: cannot allow role read roles in service: %s", commLogMsg.UnauthorizedAccess, rl.Service)
			secLog.Error(errMsg)
			return nil, http.StatusForbidden, &commErr.PrivilegeError{Message: errMsg}
		}
	}

	roleBytes, err := json.Marshal(rl)
	if err != nil {
		defaultLog.WithError(err).Error("failed to marshal json response")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "failed to marshal json response"}
	}
	secLog.WithField("role", rl).Infof("%s: Return get role request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(roleBytes), http.StatusOK, nil
}

func (controller RolesController) DeleteRole(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to deleteRole")
	defer defaultLog.Trace("deleteRole return")

	// authorize rest api endpoint based on token
	ctxMap, err := authorizeEndpoint(r, []string{consts.RoleDelete}, true)
	if err != nil {
		secLog.Warningf("%s: Unauthorized delete role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	delRl, err := controller.Database.RoleStore().Retrieve(&types.RoleSearch{AllContexts: true, IDFilter: []string{id}})
	if delRl == nil || err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("Attempt to delete invalid role")
		return nil, http.StatusNotFound, nil
	}

	if delRl.Service == consts.ServiceName && contains(consts.DefaultRoles, delRl.Name) {
		defaultLog.WithError(err).WithField("id", id).Info("attempt to delete default role")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Attempt to delete default role"}
	}

	// we have obtained the role from db now. If ctxMap is not nil, we need to make sure that user has access to
	// a role in the token that can read this role
	if ctxMap != nil {
		if _, ok := (*ctxMap)[delRl.Service]; !ok {
			errMsg := fmt.Sprintf("%s: cannot allow deleting roles in service: %s", commLogMsg.UnauthorizedAccess, delRl.Service)
			secLog.Warningf(errMsg)
			return nil, http.StatusForbidden, &commErr.PrivilegeError{Message: errMsg}
		}
	}

	if err := controller.Database.RoleStore().Delete(*delRl); err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to delete role")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete role"}
	}
	secLog.WithField("role", delRl).Infof("%s: Role deleted by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)

	return nil, http.StatusNoContent, nil
}

func (controller RolesController) QueryRoles(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to queryRoles")
	defer defaultLog.Trace("queryRoles return")

	var validationErr error

	// authorize rest api endpoint based on token
	svcFltr, err := authorizeEndPointAndGetServiceFilter(r, []string{consts.RoleSearch})
	if err != nil {
		secLog.Warningf("%s: Unauthorized query role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query roles")
	service := r.URL.Query().Get("service")
	roleName := r.URL.Query().Get("name")
	context := r.URL.Query().Get("context")
	contextContains := r.URL.Query().Get("contextContains")
	queryAllContexts := r.URL.Query().Get("allContexts")

	if len(roleName) != 0 {
		if validationErr = ValidateRoleString(roleName); validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
	}

	if len(service) > 0 {
		if validationErr = ValidateServiceString(service); validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
	}

	if len(context) > 0 {
		if validationErr = ValidateContextString(context); validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
	}

	if len(contextContains) > 0 {
		if validationErr = ValidateContextString(contextContains); validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
	}

	// set allContexts to true - override if we get a valid entry from query parameter
	allContexts := true
	if getAllContexts, err := strconv.ParseBool(queryAllContexts); err == nil {
		allContexts = getAllContexts
	}

	filter := types.RoleSearch{
		RoleInfo: aasModel.RoleInfo{
			Service: service,
			Name:    roleName,
			Context: context,
		},
		ContextContains: contextContains,
		ServiceFilter:   svcFltr,
		AllContexts:     allContexts,
	}

	roles, err := controller.Database.RoleStore().RetrieveAll(&filter)
	if err != nil {
		defaultLog.WithError(err).WithField("filter", filter).Info("failed to retrieve roles")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "failed to retrieve roles"}
	}

	rolesBytes, err := json.Marshal(roles)
	secLog.Infof("%s: Return role query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(rolesBytes), http.StatusOK, nil
}

func (controller RolesController) UpdateRole(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	return nil, http.StatusNotImplemented, &commErr.ResourceError{Message: ""}
}

func contains(strArr [5]string, str string) bool {
	for _, s := range strArr {
		if s == str {
			return true
		}
	}
	return false
}
