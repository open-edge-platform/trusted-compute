/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/config"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/common"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/authservice/constants"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/context"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/aas"
	"github.com/nats-io/nkeys"
	log "github.com/sirupsen/logrus"
)

type CredentialsController struct {
	UserCredentialValidity time.Duration
	AccountSeedFile        string
}

func (controller CredentialsController) CreateCredentials(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/credentials_controller:CreateCredentials() Entering")
	defer defaultLog.Trace("controllers/credentials_controller:CreateCredentials() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/credentials_controller:CreateCredentials() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.BadRequestError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var createCredReq aas.CreateCredentialsReq
	err := dec.Decode(&createCredReq)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/credentials_controller:CreateCredentials() %s : Failed to "+
			"decode credential creation request JSON", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.BadRequestError{Message: "Unable to decode JSON request body"}
	}

	var username string
	if strings.ToUpper(createCredReq.ComponentType) == constants.ComponentTypeTa {
		if createCredReq.Parameters != nil && createCredReq.Parameters.TaHostId != nil {
			err = validation.ValidateHostname(*createCredReq.Parameters.TaHostId)
			if err != nil {
				secLog.WithError(err).Errorf("controllers/credentials_controller:CreateCredentials() %s : Invalid "+
					"host FQDN provided in request body", commLogMsg.InvalidInputBadEncoding)
				return nil, http.StatusBadRequest, &commErr.BadRequestError{Message: "Invalid host FQDN provided"}
			}
			username = *createCredReq.Parameters.TaHostId
		} else {
			return nil, http.StatusBadRequest, &commErr.BadRequestError{Message: "Host FQDN is not provided"}
		}
	} else if strings.ToUpper(createCredReq.ComponentType) == constants.ComponentTypeHvs {
		username = constants.HvsUserName
	} else {
		return nil, http.StatusBadRequest, &commErr.BadRequestError{Message: "Component specified in type is not supported"}
	}

	if !validateComponentType(r, strings.ToUpper(createCredReq.ComponentType)) {
		secLog.Errorf("controllers/credentials_controller:CreateCredentials() %s : Component details in request "+
			"do not match token context", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusUnauthorized, &commErr.ResourceError{Message: "Component details in request do not match " +
			"token context"}
	}
	userKeyPair, err := nkeys.CreateUser()
	if err != nil {
		log.WithError(err).Error("controllers/credentials_controller:CreateCredentials() Error creating user key pair")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error creating user nkeys"}
	}
	userSeed, err := userKeyPair.Seed()
	if err != nil {
		log.WithError(err).Error("controllers/credentials_controller:CreateCredentials() Error fetching user seed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error fetching user seed"}
	}

	accountSeedBytes, err := ioutil.ReadFile(controller.AccountSeedFile)
	if err != nil {
		log.WithError(err).Error("controllers/credentials_controller:CreateCredentials() Error reading account " +
			"seed from file")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error reading account seed from file"}
	}

	accountKeyPair, err := nkeys.FromSeed(accountSeedBytes)
	if err != nil {
		log.WithError(err).Error("controllers/credentials_controller:CreateCredentials() Error creating account key pair")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Error creating account key pair"}
	}

	userToken, err := common.CreateJWTToken(userKeyPair, accountKeyPair,
		constants.User, strings.ToUpper(createCredReq.ComponentType), config.NatsEntityInfo{Name: username,
			CredentialValidity: controller.UserCredentialValidity})
	if err != nil {
		log.WithError(err).Error("controllers/credentials_controller:CreateCredentials() Error creating token for user")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "controllers/credentials_controller:" +
			"CreateCredentials() Error creating token for user"}
	}
	log.Debug("controllers/credentials_controller:CreateCredentials() User token is: ", userToken)

	formattedUserCred := fmt.Sprintf("-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n"+
		"************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign "+
		"and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n-----BEGIN USER NKEY SEED-----"+
		"\n%s\n------END USER NKEY SEED------\n\n*************************************************************"+
		"", userToken, userSeed)

	return formattedUserCred, http.StatusCreated, nil
}

func validateComponentType(r *http.Request, componentType string) bool {
	roles, err := context.GetUserRoles(r)
	if err != nil {
		return false
	}

	requiredRole := aas.RoleInfo{
		Service: constants.ServiceName,
		Name:    constants.CredentialCreatorRoleName,
	}

	if componentType == constants.ComponentTypeHvs {
		requiredRole.Context = "type=" + constants.ComponentTypeHvs
	} else if componentType == constants.ComponentTypeTa {
		requiredRole.Context = "type=" + constants.ComponentTypeTa
	} else {
		log.Error("controllers/credentials_controller: validateComponentType() Invalid component type provided")
		return false
	}

	for _, role := range roles {
		if role == requiredRole {
			return true
		}
	}

	return false
}
