/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/domain"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	jwtauth "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/jwt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	aasModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"

	"net/http"

	authcommon "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/types"

	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
)

type roleClaims struct {
	Roles       types.Roles               `json:"roles"`
	Permissions []aasModel.PermissionInfo `json:"permissions,omitempty"`
}

type JwtTokenController struct {
	Database     domain.AASDatabase
	TokenFactory *jwtauth.JwtFactory
}

func (controller JwtTokenController) CreateJwtToken(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to createJwtToken")
	defer defaultLog.Trace("createJwtToken return")

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var uc aasModel.UserCred
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&uc)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	validationErr := validation.ValidateUserNameString(uc.UserName)
	if validationErr != nil {
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: validationErr.Error()}
	}

	validationErr = validation.ValidatePasswordString(uc.Password)
	if validationErr != nil {
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: validationErr.Error()}
	}

	u := controller.Database.UserStore()

	if httpStatus, err := authcommon.HttpHandleUserAuth(u, uc.UserName, uc.Password); err != nil {
		secLog.Warningf("%s: User [%s] authentication failed, requested from %s: ", commLogMsg.AuthenticationFailed, uc.UserName, r.RemoteAddr)
		return nil, httpStatus, &commErr.ResourceError{Message: err.Error()}
	}
	secLog.Infof("%s: User [%s] authenticated, requested from %s: ", commLogMsg.AuthenticationSuccess, uc.UserName, r.RemoteAddr)

	roles, err := u.GetRoles(types.User{Name: uc.UserName}, nil, false)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Database error: unable to retrieve roles"}
	}
	perms, err := u.GetPermissions(types.User{Name: uc.UserName}, nil)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Database error: unable to retrieve permissions"}
	}

	jwt, err := controller.TokenFactory.Create(&roleClaims{Roles: roles, Permissions: perms}, uc.UserName, 0)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "could not generate token"}
	}

	secLog.Infof("%s: Return JWT token of user [%s] to: %s", commLogMsg.TokenIssued, uc.UserName, r.RemoteAddr)
	return jwt, http.StatusOK, nil
}

func (controller JwtTokenController) CreateCustomClaimsJwtToken(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {

	defaultLog.Trace("call to createCustomClaimsJwtToken")
	defer defaultLog.Trace("createCustomClaimsJwtToken return")

	if r.ContentLength == 0 {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	var cc aasModel.CustomClaims
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	err := dec.Decode(&cc)
	if err != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode request body"}
	}

	validationErr := validation.ValidateUserNameString(cc.Subject)
	if validationErr != nil {
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid subject provided"}
	}

	jwt, err := controller.TokenFactory.Create(&cc.Claims, cc.Subject, time.Duration(cc.ValiditySecs)*time.Second)
	if err != nil {
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "could not generate token"}
	}

	secLog.Infof("%s: Created custom claims for user/subject %s with token valid for %d seconds", commLogMsg.TokenIssued, cc.Subject, cc.ValiditySecs)
	return jwt, http.StatusOK, nil
}
