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
	"strings"

	authcommon "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/auth"
	comctx "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	aasModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

type UsersController struct {
	Database domain.AASDatabase
}

func (controller UsersController) CreateUser(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to createUser")
	defer defaultLog.Trace("createUser return")
	var uc aasModel.UserCreate

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&uc)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// validate user fields
	validationErr := validation.ValidateUserNameString(uc.Name)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = validation.ValidatePasswordString(uc.Password)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	existingUser, err := controller.Database.UserStore().Retrieve(types.User{Name: uc.Name})
	if existingUser != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "same user exists"}
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(uc.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	created, err := controller.Database.UserStore().Create(types.User{Name: uc.Name, PasswordHash: passwordHash, PasswordCost: bcrypt.DefaultCost})
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.WithField("user", created).Infof("%s: User created by: %s", commLogMsg.UserAdded, r.RemoteAddr)

	createdUserBytes, err := json.Marshal(created)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	return string(createdUserBytes), http.StatusCreated, nil
}

func (controller UsersController) GetUser(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to getUser")
	defer defaultLog.Trace("getUser return")

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	u, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("Failed to retrieve user")
		return nil, http.StatusNotFound, nil
	}
	userBytes, err := json.Marshal(u)
	secLog.WithField("user", u).Infof("%s: Return get user request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(userBytes), http.StatusOK, nil
}

func (controller UsersController) UpdateUser(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to updateUser")
	defer defaultLog.Trace("updateUser return")

	var uc aasModel.UserCreate

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	u, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
		return nil, http.StatusNotFound, nil
	}

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&uc)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}
	if uc.Name == "" && uc.Password == "" {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "No data to change"}
	}

	// create a structure for the updated user
	updatedUser := types.User{ID: id}

	// validate user fields and set the attributes for the user that we want to change
	if uc.Name != "" {
		validationErr := validation.ValidateUserNameString(uc.Name)
		if validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
		tempUser, err := controller.Database.UserStore().Retrieve(types.User{Name: uc.Name})
		if err == nil && tempUser.ID != id {
			defaultLog.Warningf("new username %s  for changeUser is used by user: %s", uc.Name, tempUser.ID)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "supplied username belongs to another user"}
		}
		updatedUser.Name = uc.Name
	} else {
		updatedUser.Name = u.Name
	}

	if uc.Password != "" {
		validationErr = validation.ValidatePasswordString(uc.Password)
		if validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
		updatedUser.PasswordHash, err = bcrypt.GenerateFromPassword([]byte(uc.Password), bcrypt.DefaultCost)
		if err != nil {
			defaultLog.WithError(err).Error("could not generate password when attempting to update user : ", id)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Cannot complete request"}
		}
		updatedUser.PasswordCost = bcrypt.DefaultCost
	} else {
		updatedUser.PasswordHash = u.PasswordHash
		updatedUser.PasswordCost = u.PasswordCost
	}

	err = controller.Database.UserStore().Update(updatedUser)
	if err != nil {
		defaultLog.WithError(err).Error("database error while attempting to change user:", id)
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "cannot complete request"}
	}
	secLog.Infof("%s: User %s changed by: %s", commLogMsg.PrivilegeModified, id, r.RemoteAddr)

	return nil, http.StatusOK, nil

}

func (controller UsersController) DeleteUser(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to deleteUser")
	defer defaultLog.Trace("deleteUser return")

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	delUsr, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if delUsr == nil || err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("attempt to delete invalid user")
		return nil, http.StatusNotFound, nil
	}

	if err := controller.Database.UserStore().Delete(*delUsr); err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.WithField("user", delUsr).Infof("%s: User deleted by: %s", commLogMsg.UserDeleted, r.RemoteAddr)

	return nil, http.StatusNoContent, nil
}

func (controller UsersController) QueryUsers(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to queryUsers")
	defer defaultLog.Trace("queryUsers return")

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query users")
	userName := r.URL.Query().Get("name")

	if len(userName) != 0 {
		if validationErr := validation.ValidateUserNameString(userName); validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
		}
	}

	filter := types.User{
		Name: userName,
	}

	users, err := controller.Database.UserStore().RetrieveAll(filter)
	if err != nil {
		defaultLog.WithError(err).WithField("filter", filter).Error("failed to retrieve users")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	userBytes, err := json.Marshal(users)
	if err != nil {
		defaultLog.WithError(err).Error("Failed to marshal user content to JSON")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.Infof("%s: Return user query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(userBytes), http.StatusOK, nil
}

func (controller UsersController) AddUserRoles(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to addUserRoles")
	defer defaultLog.Trace("addUserRoles return")

	// authorize rest api endpoint based on token
	svcFltr, err := authorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleCreate})
	if err != nil {
		secLog.Warningf("%s: Unauthorized add user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var rids aasModel.RoleIDs
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&rids)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if len(rids.RoleUUIDs) == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "At least one role id is required"}
	}

	for _, rid := range rids.RoleUUIDs {
		validationErr = validation.ValidateUUIDv4(rid)
		if validationErr != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "One or more role ids is not a valid uuid"}
		}
	}

	// we need to retrieve roles to add by their ids. So we pass in empty filter for role
	// We restrict roles by the privilege use the filter by id
	roles, err := controller.Database.RoleStore().RetrieveAll(&types.RoleSearch{
		IDFilter:      rids.RoleUUIDs,
		ServiceFilter: svcFltr,
		AllContexts:   true,
	})

	if err != nil {
		defaultLog.WithError(err).Info("failed to retrieve roles")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "failed to retrieve roles"}
	}

	// if the number of roles returned from the db does not match the number
	// provided in json, then abort the association(s)
	if len(roles) != len(rids.RoleUUIDs) {
		defaultLog.Errorf("could not find matching role or user does not have authorization - requested roles - %s", rids.RoleUUIDs)
		errMsg := fmt.Sprintf("could not find matching role or user does not have authorization - requested roles - %s", rids.RoleUUIDs)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: errMsg}
	}

	u, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
		errMsg := fmt.Sprintf("failed to retrieve user: %s", id)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: errMsg}
	}

	err = controller.Database.UserStore().AddRoles(*u, roles, true)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	secLog.WithField("user", u).Infof("%s: Roles added by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)

	return nil, http.StatusCreated, nil
}

func (controller UsersController) QueryUserRoles(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to queryUserRoles")
	defer defaultLog.Trace("queryUserRoles return")

	// authorize rest api endpoint based on token
	svcFltr, err := authorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleSearch})
	if err != nil {
		secLog.Warningf("%s: Unauthorized add user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query users")
	roleName := r.URL.Query().Get("name")
	service := r.URL.Query().Get("service")
	context := r.URL.Query().Get("context")
	contextContains := r.URL.Query().Get("contextContains")
	queryAllContexts := r.URL.Query().Get("allContexts")

	if len(roleName) != 0 {
		if validationErr := ValidateRoleString(roleName); validationErr != nil {
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

	roleSearchFilter := &types.RoleSearch{
		RoleInfo:        aasModel.RoleInfo{Service: service, Name: roleName, Context: context},
		ContextContains: contextContains,
		AllContexts:     allContexts,
		ServiceFilter:   svcFltr,
	}

	userRoles, err := controller.Database.UserStore().GetRoles(types.User{ID: id}, roleSearchFilter, true)
	if err != nil {
		defaultLog.WithError(err).Error("failed to retrieve user roles")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	userRoleBytes, err := json.Marshal(userRoles)
	if err != nil {
		defaultLog.WithError(err).Error("Failed to marshal user roles to JSON")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}

	secLog.Infof("%s: Return user permission query request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(userRoleBytes), http.StatusOK, nil
}

func (controller UsersController) QueryUserPermissions(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to QueryUserPermissions")
	defer defaultLog.Trace("QueryUserPermissions return")
	// authorize rest api endpoint based on token
	svcFltr, err := authorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleSearch})
	if err != nil {
		secLog.Warningf("%s: Unauthorized query user permissions attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query users")
	roleName := r.URL.Query().Get("name")
	service := r.URL.Query().Get("service")
	context := r.URL.Query().Get("context")
	contextContains := r.URL.Query().Get("contextContains")
	queryAllContexts := r.URL.Query().Get("allContexts")

	if len(roleName) != 0 {
		if validationErr := ValidateRoleString(roleName); validationErr != nil {
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

	roleSearchFilter := &types.RoleSearch{
		RoleInfo:        aasModel.RoleInfo{Service: service, Name: roleName, Context: context},
		ContextContains: contextContains,
		AllContexts:     allContexts,
		ServiceFilter:   svcFltr,
	}

	userPermissions, err := controller.Database.UserStore().GetPermissions(types.User{ID: id}, roleSearchFilter)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Error("error while obtaining permissions for user")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Database error : querying user permissions"}
	}

	userPermissionsBytes, err := json.Marshal(userPermissions)
	if err != nil {
		defaultLog.WithError(err).Error("Failed to marshal user permissions to JSON")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.Infof("%s: Return user permissions query request to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return string(userPermissionsBytes), http.StatusOK, nil
}

func (controller UsersController) GetUserRoleById(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to GetUserRoleById")
	defer defaultLog.Trace("GetUserRoleById return")

	id := mux.Vars(r)["id"]
	rid := mux.Vars(r)["role_id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}
	validationErr = validation.ValidateUUIDv4(rid)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}
	u, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "User ID provided does not exist"}
	}
	role, err := controller.Database.UserStore().GetUserRoleByID(*u, rid)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).WithField("rid", rid).Info("failed to get role from user")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Role ID provided is not associated to the User ID"}
	}
	secLog.WithField("user", *u).Infof("%s: User role found by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)

	roleBytes, err := json.Marshal(role)
	if err != nil {
		defaultLog.WithError(err).Error("Failed to marshal user role to JSON")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: err.Error()}
	}
	return string(roleBytes), http.StatusOK, nil
}

func (controller UsersController) DeleteUserRole(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to deleteUserRole")
	defer defaultLog.Trace("deleteUserRole return")
	// authorize rest api endpoint based on token
	svcFltr, err := authorizeEndPointAndGetServiceFilter(r, []string{consts.UserRoleDelete})
	if err != nil {
		secLog.Warningf("%s: Unauthorized delete user role attempt from: %s", commLogMsg.UnauthorizedAccess, r.RemoteAddr)
		return nil, http.StatusUnauthorized, err
	}

	id := mux.Vars(r)["id"]
	rid := mux.Vars(r)["role_id"]

	validationErr := validation.ValidateUUIDv4(id)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = validation.ValidateUUIDv4(rid)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: validationErr.Error()}
	}

	u, err := controller.Database.UserStore().Retrieve(types.User{ID: id})
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Info("failed to retrieve user")
		if strings.Contains(err.Error(), commErr.RecordNotFound) {
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "User not found"}
		} else {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "failed to retrieve user"}
		}
	}

	err = controller.Database.UserStore().DeleteRole(*u, rid, svcFltr)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).WithField("rid", rid).Info("failed to delete role from user")
		if strings.Contains(err.Error(), commErr.RecordNotFound) {
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Role to be deleted not found"}
		} else {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "failed to delete role from user"}
		}
	}
	secLog.WithField("user", *u).Infof("%s: User roles deleted by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller UsersController) ChangePassword(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to changePassword")
	defer defaultLog.Trace("changePassword return")

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var pc aasModel.PasswordChange
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&pc)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	validationErr := validation.ValidateUserNameString(pc.UserName)
	if validationErr != nil {
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = validation.ValidatePasswordString(pc.OldPassword)
	if validationErr != nil {
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: validationErr.Error()}
	}

	if pc.NewPassword != pc.PasswordConfirm {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Confirmation password does not match"}
	}

	validationErr = validation.ValidatePasswordString(pc.NewPassword)
	if validationErr != nil {
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: validationErr.Error()}
	}

	u := controller.Database.UserStore()

	if httpStatus, err := authcommon.HttpHandleUserAuth(u, pc.UserName, pc.OldPassword); err != nil {
		secLog.Warningf("%s: User [%s] auth failed, requested from %s: ", commLogMsg.UnauthorizedAccess, pc.UserName, r.RemoteAddr)
		return nil, httpStatus, &commErr.ResourceError{Message: err.Error()}
	}

	existingUser, err := controller.Database.UserStore().Retrieve(types.User{Name: pc.UserName})
	if err != nil {
		defaultLog.WithError(err).Error("not able to retrieve existing user though he was just authenticated")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "cannot complete request"}
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(pc.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		defaultLog.WithError(err).Error("could not generate password when attempting to change password")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "cannot complete request"}
	}
	existingUser.PasswordHash = passwordHash
	existingUser.PasswordCost = bcrypt.DefaultCost
	err = controller.Database.UserStore().Update(*existingUser)
	if err != nil {
		defaultLog.WithError(err).Error("database error while attempting to change password")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "cannot complete request"}
	}
	secLog.WithField("user", existingUser.ID).Infof("%s: User %s password changed by: %s", commLogMsg.PrivilegeModified, existingUser.ID, r.RemoteAddr)

	return nil, http.StatusOK, nil
}

func authorizeEndpoint(r *http.Request, permissionNames []string, retNilCtxForEmptyCtx bool) (*map[string]aasModel.PermissionInfo, error) {
	// Check query authority
	privileges, err := comctx.GetUserPermissions(r)
	if err != nil {
		secLog.WithError(err).Error(commLogMsg.InvalidInputBadParam)
		return nil,
			&commErr.ResourceError{Message: "not able to get roles from context"}
	}
	// this function check if the user requesting to perform operation has the right roles.
	reqPermissions := aasModel.PermissionInfo{Service: consts.ServiceName, Rules: permissionNames}

	ctxMap, foundMatchingPermission := auth.ValidatePermissionAndGetPermissionsContext(privileges, reqPermissions, retNilCtxForEmptyCtx)
	if !foundMatchingPermission {
		secLog.Infof("%s: endpoint access unauthorized, request permissions: %v", commLogMsg.UnauthorizedAccess, permissionNames)
		return nil, &commErr.PrivilegeError{Message: "", StatusCode: http.StatusUnauthorized}
	}

	return ctxMap, nil
}

func authorizeEndPointAndGetServiceFilter(r *http.Request, permissionNames []string) ([]string, error) {
	ctxMap, err := authorizeEndpoint(r, permissionNames, true)
	if err != nil {
		return nil, err
	}
	svcFltr := []string{}
	if ctxMap != nil {
		for _, val := range *ctxMap {
			svcFltr = append(svcFltr, val.Context)
		}
	}
	return svcFltr, nil
}
