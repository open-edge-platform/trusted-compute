/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	hcUtil "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	model "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
)

type HostController struct {
	HStore    domain.HostStore
	HSStore   domain.HostStatusStore
	FStore    domain.FlavorStore
	FGStore   domain.FlavorGroupStore
	HCStore   domain.HostCredentialStore
	HTManager domain.HostTrustManager
	HCConfig  domain.HostControllerConfig
}

func NewHostController(hs domain.HostStore, hss domain.HostStatusStore, fs domain.FlavorStore,
	fgs domain.FlavorGroupStore, hcs domain.HostCredentialStore,
	htm domain.HostTrustManager, hcc domain.HostControllerConfig) *HostController {
	return &HostController{
		HStore:    hs,
		HSStore:   hss,
		FStore:    fs,
		FGStore:   fgs,
		HCStore:   hcs,
		HTManager: htm,
		HCConfig:  hcc,
	}
}

var hostSearchParams = map[string]bool{"id": true, "nameEqualTo": true, "nameContains": true, "hostHardwareId": true,
	"key": true, "value": true, "trusted": true, "getTrustStatus": true, "getHostStatus": true, "orderBy": true, "limit": true, "afterId": true}

var hostRetrieveParams = map[string]bool{"getReport": true, "getHostStatus": true}

func (hc *HostController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Create() Entering")
	defer defaultLog.Trace("controllers/host_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Create() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.HostCreateRequest
	err := dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Create() %s :  Failed to decode request body as HostCreateRequest", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if hc.HCConfig.VerifyQuoteForHostRegistration {

		connectionString, _, err := GenerateConnectionString(reqHost.ConnectionString, hc.HCConfig.Username,
			hc.HCConfig.Password,
			hc.HCStore)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:Create() Could not generate formatted connection string")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error generating connection string"}
		}

		hostConnector, err := hc.HCConfig.HostConnectorProvider.NewHostConnector(connectionString)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:Create() Failed " +
				"to initialize HostConnector to the host")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Target Host connection failed"}
		}

		nonce, err := hcUtil.GenerateNonce(20)
		if err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error generating nonce for TPM quote request"}
		}

		verificationNonceInBytes, tpmQuoteInBytes, aikCertificate, _, _, err := hostConnector.GetTPMQuoteResponse(nonce, nil)
		if err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error getting TPM Quote Response"}
		}

		_, _, err = hcUtil.VerifyQuoteAndGetPCRDetails(verificationNonceInBytes, tpmQuoteInBytes, aikCertificate)
		if err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "TPM Quote verification failed"}
		}
	}
	createdHost, status, err := hc.CreateHost(reqHost)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host", createdHost).Infof("%s: Host created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdHost, status, nil
}

func (hc *HostController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/host_controller:Retrieve() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), hostRetrieveParams); err != nil {
		secLog.Errorf("controllers/host_controller:Retrieve() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Debug("query hosts")
	criteria, err := PopulateHostInfoFetchCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Search() %s Invalid host info fetch criteria",
			commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid host info fetch criteria"}
	}

	id := uuid.MustParse(mux.Vars(r)["hId"])
	host, status, err := hc.retrieveHost(id, criteria)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host", host).Infof("%s: Host retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return host, status, nil
}

func (hc *HostController) Update(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Update() Entering")
	defer defaultLog.Trace("controllers/host_controller:Update() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:Update() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHost hvs.Host
	err := dec.Decode(&reqHost)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Update() %s :  Failed to decode request body as Host", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	criteria := hvs.HostCreateRequest{
		HostName:         reqHost.HostName,
		Description:      reqHost.Description,
		ConnectionString: reqHost.ConnectionString,
		FlavorgroupNames: reqHost.FlavorgroupNames,
	}

	if err := validateHostCreateCriteria(criteria); err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Update() %s : Invalid request body", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	reqHost.Id = uuid.MustParse(mux.Vars(r)["hId"])
	updatedHost, status, err := hc.UpdateHost(reqHost)
	if err != nil {
		return nil, status, err
	}

	defaultLog.Debugf("Adding host %v to flavor-verify queue", reqHost.Id)
	// Since the host has been updated, add it to the verify queue
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{reqHost.Id}, true, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:Update() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	secLog.WithField("host", updatedHost).Infof("%s: Host updated by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return updatedHost, status, nil
}

func (hc *HostController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/host_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["hId"])
	host, status, err := hc.retrieveHost(id, nil)
	if err != nil {
		return nil, status, err
	}

	if err := hc.HStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:Delete() Host delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Host"}
	}

	secLog.WithField("host", host).Infof("Host deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (hc *HostController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:Search() Entering")
	defer defaultLog.Trace("controllers/host_controller:Search() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), hostSearchParams); err != nil {
		secLog.Errorf("controllers/host_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("query hosts")
	hostFilterCriteria, err := populateHostFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Search() %s Invalid host filter criteria",
			commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid host filter criteria"}
	}

	hostInfoFetchCriteria, err := PopulateHostInfoFetchCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:Search() %s Invalid host info fetch criteria",
			commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid host info fetch criteria"}
	}

	if hostFilterCriteria.Key != "" {
		hostIds, err := hc.HSStore.FindHostIdsByKeyValue(hostFilterCriteria.Key, hostFilterCriteria.Value)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:Search() HostStatus FindHostIdsByKeyValue failed")
			return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Hosts")
		}
		if hostIds == nil {
			defaultLog.Infof("controllers/host_controller:Search() There is no such host for given key: %s and "+
				"value: %s", hostFilterCriteria.Key, hostFilterCriteria.Value)
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host with given filter criteria does not exist"}
		}
		hostFilterCriteria.IdList = hostIds
	}

	hosts, err := hc.HStore.Search(hostFilterCriteria, hostInfoFetchCriteria)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:Search() Host search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Hosts")
	}

	var next, prev string
	if hostFilterCriteria.OrderBy == "" && len(hosts) > 0 {
		lastRowId := hosts[len(hosts)-1].RowId
		next, prev = GetNextAndPrevValues(hostFilterCriteria.Limit, hostFilterCriteria.AfterId, lastRowId, len(hosts))
	}

	hostCollection := hvs.HostCollection{
		Hosts: hosts, Next: next, Previous: prev,
	}

	secLog.Infof("%s: Hosts searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostCollection, http.StatusOK, nil
}

func (hc *HostController) CreateHost(reqHost hvs.HostCreateRequest) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:CreateHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:CreateHost() Leaving")

	if reqHost.HostName == "" || reqHost.ConnectionString == "" {
		secLog.Error("controllers/host_controller:CreateHost() Host connection string and host name must be specified")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host connection string and host name must be specified"}
	}

	if err := validateHostCreateCriteria(reqHost); err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:CreateHost() %s Invalid host data", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid host data"}
	}

	existingHosts, err := hc.HStore.Search(&models.HostFilterCriteria{
		NameEqualTo: reqHost.HostName}, nil)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	if existingHosts != nil && len(existingHosts) > 0 {
		secLog.WithField("Name", existingHosts[0].HostName).Warningf("%s: Trying to create duplicate Host", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host with this name already exist"}
	}

	connectionString, credential, err := GenerateConnectionString(reqHost.ConnectionString,
		hc.HCConfig.Username,
		hc.HCConfig.Password,
		hc.HCStore)

	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Could not generate formatted connection string")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	defaultLog.Debugf("Connecting to host to get the hardware UUID of the host : %s", reqHost.HostName)
	var hostState hvs.HostState
	// connect to the host and retrieve the host info
	hostInfo, err := hc.getHostInfo(connectionString)
	if err != nil {
		hostState = utils.DetermineHostState(err)
		defaultLog.Warnf("Could not connect to host, hardware UUID will not be set: %s", hostState.String())
	}

	var hwUuid *uuid.UUID = nil
	if hostInfo != nil && hostInfo.HardwareUUID != "" {
		hwid, err := uuid.Parse(hostInfo.HardwareUUID)
		if err == nil {
			hwUuid = &hwid
		}
	}

	var fgNames []string
	if len(reqHost.FlavorgroupNames) != 0 {
		fgNames = reqHost.FlavorgroupNames
	} else if hostInfo != nil && hostInfo.HardwareUUID != "" {
		// if the host is reachable and no flavorgroups are provided in the request, assign the host to "automatic" flavorgroup
		defaultLog.Debug("Flavorgroup names not present in request, associating with default ones")
		fgNames = append(fgNames, models.FlavorGroupsAutomatic.String())
	}

	// Link to default software and workload groups if host is linux and if the specific flavorgroups weren't a part of host create criteria
	if hostInfo != nil && utils.IsLinuxHost(hostInfo) && len(reqHost.FlavorgroupNames) == 0 {
		defaultLog.Debug("Host is linux, associating with default software flavorgroups")
		swFgs := utils.GetDefaultSoftwareFlavorGroups(hostInfo.InstalledComponents)
		fgNames = append(fgNames, swFgs...)
	}
	var flavorGroups []hvs.FlavorGroup
	if len(fgNames) > 0 {
		flavorGroups, err = GetFlavorGroups(hc.FGStore, fgNames, nil)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host FlavorGroup not found ")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
	}
	// remove credentials from connection string for host table storage
	csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
	defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

	host := &hvs.Host{
		HostName:         reqHost.HostName,
		Description:      reqHost.Description,
		ConnectionString: csWithoutCredentials,
		HardwareUuid:     hwUuid,
		FlavorgroupNames: fgNames,
	}

	createdHost, err := hc.HStore.Create(host)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host"}
	}

	// create credential
	var hostCredential models.HostCredential
	hostCredential.HostId = createdHost.Id
	hostCredential.HostName = createdHost.HostName
	hostCredential.Credential = credential
	if createdHost.HardwareUuid != nil {
		hostCredential.HardwareUuid = models.NewHwUUID(*createdHost.HardwareUuid)
	}

	_, err = hc.HCStore.Create(&hostCredential)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host Credential create failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host Credential"}
	}

	defaultLog.Debugf("Associating host %s with flavorgroups %+q", reqHost.HostName, fgNames)
	if len(fgNames) > 0 {
		if err := hc.linkFlavorgroupsToHost(createdHost.Id, flavorGroups); err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host FlavorGroup association failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
		}
	}

	defaultLog.Debugf("Associating host %s with all host unique flavors", reqHost.HostName)
	if err := hc.linkHostUniqueFlavorsToHost(createdHost); err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:CreateHost() Host Unique flavor association failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with host unique flavors"}
	}

	defaultLog.Debugf("Adding host %s to flavor-verify queue", reqHost.HostName)
	// Since we are adding a new host, the forceUpdate flag should be set to true so that
	// we connect to the host and get the latest host manifest to verify against.
	defer func() {
		verr := hc.HTManager.VerifyHostsAsync([]uuid.UUID{createdHost.Id}, true, false)
		if verr != nil {
			defaultLog.WithError(verr).Error("controllers/host_controller:CreateHost() Host to Flavor Verify Queue addition failed")
		}
	}()

	return createdHost, http.StatusCreated, nil
}

func (hc *HostController) UpdateHost(reqHost hvs.Host) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:UpdateHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:UpdateHost() Leaving")

	_, status, err := hc.retrieveHost(reqHost.Id, nil)
	if err != nil {
		return nil, status, err
	}

	if reqHost.ConnectionString != "" {
		connectionString, credential, err := GenerateConnectionString(reqHost.ConnectionString,
			hc.HCConfig.Username,
			hc.HCConfig.Password,
			hc.HCStore)

		if err != nil {
			defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Could not generate formatted connection string")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}

		// remove credentials from connection string for host table storage
		csWithoutCredentials := utils.GetConnectionStringWithoutCredentials(connectionString)
		defaultLog.Debugf("connection string without credentials : %s", csWithoutCredentials)

		reqHost.ConnectionString = csWithoutCredentials

		// update credential
		hostCredential, err := hc.HCStore.FindByHostId(reqHost.Id)
		if err != nil {
			if strings.Contains(err.Error(), commErr.RowsNotFound) {
				defaultLog.Debugf("controllers/host_controller:UpdateHost() Host Credential with specified host id could not be located")
				hostCredential = nil
			} else {
				defaultLog.WithError(err).WithField("hostId", reqHost.Id).Error("controllers/host_controller:UpdateHost() Host Credential retrieve failed")
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host Credential from database"}
			}
		}

		if hostCredential != nil {
			hostCredential.Credential = credential
			if err = hc.HCStore.Update(hostCredential); err != nil {
				defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Host Credential update failed")
				return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host Credential"}
			}
		}
	}

	if err := hc.HStore.Update(&reqHost); err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Host update failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to update Host"}
	}

	updatedHost, err := hc.HStore.Retrieve(reqHost.Id, nil)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:UpdateHost() Host retrieve failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host"}
	}

	if len(reqHost.FlavorgroupNames) != 0 {
		defaultLog.Debugf("Associating host %s with flavorgroups : %+q", updatedHost.HostName, reqHost.FlavorgroupNames)

		fgroup, err := GetFlavorGroups(hc.FGStore, reqHost.FlavorgroupNames, nil)
		if err != nil {
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
		}
		if err := hc.linkFlavorgroupsToHost(updatedHost.Id, fgroup); err != nil {
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with flavorgroups"}
		}

		updatedHost.FlavorgroupNames = reqHost.FlavorgroupNames
	}

	return updatedHost, http.StatusOK, nil
}

func (hc *HostController) retrieveHost(id uuid.UUID, criteria *models.HostInfoFetchCriteria) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:retrieveHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:retrieveHost() Leaving")

	host, err := hc.HStore.Retrieve(id, criteria)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:retrieveHost() Host with specified id could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Host with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Error("controllers/host_controller:retrieveHost() Host retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host from database"}
		}
	}
	return host, http.StatusOK, nil
}

// GenerateConnectionString creates a formatted connection string. If the username and password are not specified, then it would retrieve it
// from the credential table and forms the complete connection string.
func GenerateConnectionString(cs, username, password string, hc domain.HostCredentialStore) (string, string, error) {
	defaultLog.Trace("controllers/host_controller:GenerateConnectionString() Entering")
	defer defaultLog.Trace("controllers/host_controller:GenerateConnectionString() Leaving")

	vc, err := hcUtil.GetConnectorDetails(cs)
	if err != nil {
		return "", "", errors.Wrap(err, "Could not get vendor details from connection string")
	}

	var credential string
	if vc.Vendor != hcConstants.VendorVMware {
		credential = fmt.Sprintf("u=%s;p=%s", username, password)
		cs = fmt.Sprintf("%s;%s", cs, credential)
	} else {
		//if credentials not specified in connection string, retrieve from credential table
		if !strings.Contains(cs, "u=") || !strings.Contains(cs, "p=") {
			var hostname string
			// If the connection string is for VMware, we would have this substring from which we need to extract
			// the host name. Otherwise we can extract the host name after the https:// in the connection string.
			if strings.Contains(cs, "h=") {
				hostname = vc.Configuration.Hostname
			} else {
				hostname = strings.Split(strings.Split(cs, "//")[1], ":")[0]
			}

			if hostname == "" {
				return "", "", errors.New("Host connection string is formatted incorrectly, cannot retrieve host name")
			}

			// Fetch credentials from db
			hostCredential, err := hc.FindByHostName(hostname)
			if err != nil {
				return "", "", errors.Wrap(err, "Credentials must be provided for the host connection string")
			}

			credential = hostCredential.Credential
			cs = fmt.Sprintf("%s;%s", cs, credential)
			username = strings.Split(credential, ";")[0]
			password = strings.Split(credential, ";")[1]
		} else {
			username = vc.Configuration.Username
			password = vc.Configuration.Password
			credential = fmt.Sprintf("u=%s;p=%s", username, password)
		}
	}

	// validate credential information values are not null or empty
	if credential == "" {
		return "", "", errors.New("Credentials must be provided for the host connection string")
	}

	if username == "" {
		return "", "", errors.New("Username must be provided in the host connection string")
	}

	if password == "" {
		return "", "", errors.New("Password must be provided in the host connection string")
	}

	return cs, credential, nil
}

func (hc *HostController) getHostInfo(cs string) (*model.HostInfo, error) {
	defaultLog.Trace("controllers/host_controller:getHostInfo() Entering")
	defer defaultLog.Trace("controllers/host_controller:getHostInfo() Leaving")

	hostConnector, err := hc.HCConfig.HostConnectorProvider.NewHostConnector(cs)
	if err != nil {
		return nil, errors.Wrap(err, "Could not instantiate host connector")
	}

	hostInfo, err := hostConnector.GetHostDetails()
	return &hostInfo, err
}

func (hc *HostController) linkFlavorgroupsToHost(hostId uuid.UUID, fgroups []hvs.FlavorGroup) error {
	defaultLog.Trace("controllers/host_controller:linkFlavorgroupsToHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:linkFlavorgroupsToHost() Leaving")

	flavorgroupIds := []uuid.UUID{}
	for _, flavorgroup := range fgroups {
		linkExists, err := hc.flavorGroupHostLinkExists(hostId, flavorgroup.ID)
		if err != nil {
			return errors.Wrap(err, "Could not check host-flavorgroup link existence")
		}
		if !linkExists {
			flavorgroupIds = append(flavorgroupIds, flavorgroup.ID)
		}
	}

	defaultLog.Debugf("Linking host %v with flavorgroups %+q", hostId, flavorgroupIds)
	if err := hc.HStore.AddFlavorgroups(hostId, flavorgroupIds); err != nil {
		return errors.Wrap(err, "Could not create host-flavorgroup links")
	}

	return nil
}

func (hc *HostController) linkHostUniqueFlavorsToHost(newHost *hvs.Host) error {
	defaultLog.Trace("controllers/host_controller:linkHostUniqueFlavorsToHost() Entering")
	defer defaultLog.Trace("controllers/host_controller:linkHostUniqueFlavorsToHost() Leaving")

	// ignore if hwUuid is nil - need to check for nil for the pointer as well as invalid uuid
	if newHost == nil || newHost.HardwareUuid == nil || *newHost.HardwareUuid == uuid.Nil {
		return nil
	}

	// get the associated flavors
	signedFlavors, err := hc.FStore.Search(&models.FlavorVerificationFC{
		FlavorFC: models.FlavorFilterCriteria{
			Key:   "hardware_uuid",
			Value: newHost.HardwareUuid.String(),
		},
	})
	if err != nil {
		return errors.Wrap(err, "error while searching host unique flavors")
	}

	var flavorIds []uuid.UUID
	for _, signedFlavor := range signedFlavors {
		flavorIds = append(flavorIds, signedFlavor.Flavor.Meta.ID)
	}

	if len(flavorIds) == 0 {
		return nil
	}
	defaultLog.Debugf("Linking host %v with flavors %+q", newHost.Id, flavorIds)
	if _, err := hc.HStore.AddHostUniqueFlavors(newHost.Id, flavorIds); err != nil {
		return errors.Wrap(err, "Could not create host-unique flavors link")
	}

	return nil
}

func GetFlavorGroups(fGStore domain.FlavorGroupStore, flavorgroupNames []string, flavorTemplateIds []uuid.UUID) ([]hvs.FlavorGroup, error) {
	flavorgroups := []hvs.FlavorGroup{}
	var missingFlavorGroups []string
	for _, flavorgroupName := range flavorgroupNames {
		existingFlavorGroups, err := fGStore.Search(&models.FlavorGroupFilterCriteria{
			NameEqualTo: flavorgroupName,
		})
		if err != nil {
			return nil, errors.New("Error when searching flavor group")
		}
		if existingFlavorGroups == nil || len(existingFlavorGroups) == 0 {
			missingFlavorGroups = append(missingFlavorGroups, flavorgroupName)
		} else {
			flavorgroups = append(flavorgroups, existingFlavorGroups...)
		}
	}
	if len(missingFlavorGroups) > 0 {
		return nil, errors.New("Flavor group record not found: " + strings.Join(missingFlavorGroups[:], ", "))
	}
	return flavorgroups, nil
}

func (hc *HostController) flavorGroupHostLinkExists(hostId, flavorgroupId uuid.UUID) (bool, error) {
	defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Entering")
	defer defaultLog.Trace("controllers/host_controller:flavorGroupHostLinkExists() Leaving")

	// retrieve the host-flavorgroup link using host id and flavorgroup id
	_, err := hc.HStore.RetrieveFlavorgroup(hostId, flavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			return false, nil
		} else {
			return false, err
		}
	}
	return true, nil
}

func validateHostCreateCriteria(host hvs.HostCreateRequest) error {
	defaultLog.Trace("controllers/host_controller:validateHostCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:validateHostCreateCriteria() Leaving")

	if host.HostName != "" {
		if err := validation.ValidateHostname(host.HostName); err != nil {
			return errors.Wrap(err, "Valid Host Name must be specified")
		}
	}
	if host.ConnectionString != "" {
		err := utils.ValidateConnectionString(host.ConnectionString)
		if err != nil {
			return errors.Wrap(err, "Invalid host connection string")
		}
	}
	if host.Description != "" {
		if err := validation.ValidateStrings([]string{host.Description}); err != nil {
			return errors.Wrap(err, "Valid Host Description must be specified")
		}
	}
	if len(host.FlavorgroupNames) != 0 {
		for _, flavorgroup := range host.FlavorgroupNames {
			if flavorgroup == "" {
				return errors.New("Valid Flavorgroup Names must be specified, empty name is not allowed")
			}
		}
		if err := validation.ValidateStrings(host.FlavorgroupNames); err != nil {
			return errors.Wrap(err, "Valid Flavorgroup Names must be specified")
		}
	}
	return nil
}

func populateHostFilterCriteria(params url.Values) (*models.HostFilterCriteria, error) {
	defaultLog.Trace("controllers/host_controller:populateHostFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:populateHostFilterCriteria() Leaving")

	var criteria models.HostFilterCriteria

	if params.Get("id") != "" {
		id, err := uuid.Parse(params.Get("id"))
		if err != nil {
			return nil, errors.New("Invalid id query param value, must be UUID")
		}
		criteria.Id = id

	} else if params.Get("nameEqualTo") != "" {
		name := params.Get("nameEqualTo")
		if err := validation.ValidateHostname(name); err != nil {
			return nil, errors.Wrap(err, "Valid contents for nameEqualTo must be specified")
		}
		criteria.NameEqualTo = name

	} else if params.Get("nameContains") != "" {
		name := params.Get("nameContains")
		if err := validation.ValidateHostname(name); err != nil {
			return nil, errors.Wrap(err, "Valid contents for nameContains must be specified")
		}
		criteria.NameContains = name

	} else if params.Get("hostHardwareId") != "" {
		hwid, err := uuid.Parse(params.Get("hostHardwareId"))
		if err != nil {
			return nil, errors.New("Invalid hostHardwareId query param value, must be UUID")
		}
		criteria.HostHardwareId = hwid

	} else if params.Get("key") != "" && params.Get("value") != "" {
		key := params.Get("key")
		value := params.Get("value")
		if err := validation.ValidateStrings([]string{key, value}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for key and value must be specified")
		}
		criteria.Key = key
		criteria.Value = value
	} else if params.Get("trusted") != "" {
		trustStatus, err := strconv.ParseBool(params.Get("trusted"))
		if err != nil {
			return nil, errors.New("Invalid trusted query param value, must be true/false")
		}
		criteria.Trusted = &trustStatus
	}

	if params.Get("orderBy") != "" && (params.Get("limit") != "" || params.Get("afterId") != "") {
		return nil, errors.New("Both Orderby and Limit/Afterid cannot be set together")
	}

	if params.Get("orderBy") != "" {
		orderType, err := models.GetOrderType(params.Get("orderBy"))
		if err != nil {
			return nil, errors.New("Invalid orderBy query param value, must be asc/desc")
		}
		criteria.OrderBy = orderType
	}

	limit, afterId, err := validation.ValidatePaginationValues(params.Get("limit"), params.Get("afterId"))
	if err != nil {
		return nil, err
	}
	criteria.Limit = limit
	criteria.AfterId = afterId

	return &criteria, nil
}

func PopulateHostInfoFetchCriteria(params url.Values) (*models.HostInfoFetchCriteria, error) {
	defaultLog.Trace("controllers/host_controller:PopulateHostInfoFetchCriteria() Entering")
	defer defaultLog.Trace("controllers/host_controller:PopulateHostInfoFetchCriteria() Leaving")

	var criteria models.HostInfoFetchCriteria

	if params.Get("getReport") != "" {
		getReport, err := strconv.ParseBool(params.Get("getReport"))
		if err != nil {
			return nil, errors.New("Invalid getReport query param value, must be boolean")
		}

		criteria.GetReport = getReport

	}
	if params.Get("getTrustStatus") != "" {
		getTrustStatus, err := strconv.ParseBool(params.Get("getTrustStatus"))
		if err != nil {
			return nil, errors.Wrap(err, "Invalid getTrustStatus query param value, must be boolean")
		}
		criteria.GetTrustStatus = getTrustStatus
	}

	if params.Get("getHostStatus") != "" {
		getHostStatus, err := strconv.ParseBool(params.Get("getHostStatus"))
		if err != nil {
			return nil, errors.Wrap(err, "Invalid getHostStatus query param value, must be boolean")
		}
		criteria.GetHostStatus = getHostStatus
	}

	return &criteria, nil
}

func (hc *HostController) AddFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:AddFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:AddFlavorgroup() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/host_controller:AddFlavorgroup() The request body was not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body was not provided"}
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var reqHostFlavorgroup hvs.HostFlavorgroupCreateRequest
	err := dec.Decode(&reqHostFlavorgroup)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/host_controller:AddFlavorgroup() %s :  Failed to decode request body as HostFlavorgroupCreateRequest", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if reqHostFlavorgroup.FlavorgroupId == uuid.Nil {
		secLog.Errorf("controllers/host_controller:AddFlavorgroup() %s : Invalid Flavorgroup Id specified in request", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Flavorgroup Id specified in request"}
	}

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	_, status, err := hc.retrieveHost(hId, nil)
	if err != nil {
		return nil, status, err
	}

	_, err = hc.FGStore.Retrieve(reqHostFlavorgroup.FlavorgroupId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", reqHostFlavorgroup.FlavorgroupId).Error("controllers/host_controller:AddFlavorgroup() Flavorgroup with specified id could not be located")
			return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Flavorgroup with specified id does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", reqHostFlavorgroup.FlavorgroupId).Error("controllers/host_controller:AddFlavorgroup() Flavorgroup retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Flavorgroup from database"}
		}
	}

	linkExists, err := hc.flavorGroupHostLinkExists(hId, reqHostFlavorgroup.FlavorgroupId)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:AddFlavorgroup() Host Flavorgroup link retrieve failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to create Host Flavorgroup link"}
	}
	if linkExists {
		secLog.WithError(err).Warningf("%s: Trying to create duplicate Host Flavorgroup link", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Host Flavorgroup link with specified ids already exist"}
	}

	defaultLog.Debugf("Linking host %v with flavorgroup %v", hId, reqHostFlavorgroup.FlavorgroupId)
	err = hc.HStore.AddFlavorgroups(hId, []uuid.UUID{reqHostFlavorgroup.FlavorgroupId})
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:AddFlavorgroup() Host Flavorgroup association failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to associate Host with Flavorgroup"}
	}

	createdHostFlavorgroup := hvs.HostFlavorgroup{
		HostId:        hId,
		FlavorgroupId: reqHostFlavorgroup.FlavorgroupId,
	}

	defaultLog.Debugf("Adding host %v to flavor-verify queue", hId)
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{hId}, false, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:AddFlavorgroup() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	secLog.WithField("host-flavorgroup-link", createdHostFlavorgroup).Infof("%s: Host Flavorgroup link created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return createdHostFlavorgroup, http.StatusCreated, nil
}

func (hc *HostController) RetrieveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:RetrieveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:RetrieveFlavorgroup() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	hostFlavorgroup, status, err := hc.retrieveFlavorgroup(hId, fgId)
	if err != nil {
		return nil, status, err
	}

	secLog.WithField("host-flavorgroup-link", hostFlavorgroup).Infof("%s: Host Flavorgroup link retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostFlavorgroup, status, nil
}

func (hc *HostController) RemoveFlavorgroup(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:RemoveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:RemoveFlavorgroup() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgId := uuid.MustParse(mux.Vars(r)["fgId"])
	hostFlavorgroup, status, err := hc.retrieveFlavorgroup(hId, fgId)
	if err != nil {
		return nil, status, err
	}

	if err := hc.HStore.RemoveFlavorgroups(hId, []uuid.UUID{fgId}); err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:RemoveFlavorgroup() Host Flavorgroup link delete failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete Host Flavorgroup link"}
	}

	defaultLog.Debugf("Adding host %v to flavor-verify queue", hId)
	//Bug-12442 - Report gets updated only if trust cache fails flavorgroup requirements or if new data is fetched from host
	//            In case of flavorgroup delete, trust cache could be valid for rest of flavorgroup so report might not get updated
	//            which needs to now exclude report information from deleted flavorgroup. Hence, force to fetch data from host so
	//            report will be updated. As this is not very frequent operation, it should be fine.
	err = hc.HTManager.VerifyHostsAsync([]uuid.UUID{hId}, true, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:RemoveFlavorgroup() Host to Flavor Verify Queue addition failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to add Host to Flavor Verify Queue"}
	}

	secLog.WithField("host-flavorgroup-link", hostFlavorgroup).Infof("Host Flavorgroup link deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (hc *HostController) SearchFlavorgroups(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:SearchFlavorgroups() Entering")
	defer defaultLog.Trace("controllers/host_controller:SearchFlavorgroups() Leaving")

	hId := uuid.MustParse(mux.Vars(r)["hId"])
	fgIds, err := hc.HStore.SearchFlavorgroups(hId)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/host_controller:SearchFlavorgroups() Host Flavorgroup links search failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Failed to search Host Flavorgroup links")
	}

	hostFlavorgroups := []hvs.HostFlavorgroup{}
	for _, fgId := range fgIds {
		hostFlavorgroups = append(hostFlavorgroups, hvs.HostFlavorgroup{
			HostId:        hId,
			FlavorgroupId: fgId,
		})
	}
	hostFlavorgroupCollection := hvs.HostFlavorgroupCollection{HostFlavorgroups: hostFlavorgroups}

	secLog.Infof("%s: Host Flavorgroup links searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostFlavorgroupCollection, http.StatusOK, nil
}

func (hc *HostController) retrieveFlavorgroup(hId, fgId uuid.UUID) (interface{}, int, error) {
	defaultLog.Trace("controllers/host_controller:retrieveFlavorgroup() Entering")
	defer defaultLog.Trace("controllers/host_controller:retrieveFlavorgroup() Leaving")

	hostFlavorgroup, err := hc.HStore.RetrieveFlavorgroup(hId, fgId)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).Error("controllers/host_controller:RetrieveFlavorgroup() Host Flavorgroup link with specified ids could not be located")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Host Flavorgroup link with specified ids does not exist"}
		} else {
			defaultLog.WithError(err).Error("controllers/host_controller:RetrieveFlavorgroup() Host Foavorgroup link retrieve failed")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host Flavorgroup link from database"}
		}
	}
	return hostFlavorgroup, http.StatusOK, nil
}

func GetNextAndPrevValues(limit int, afterId int, rowId int, lenOfResponse int) (string, string) {
	var next, prev string
	if lenOfResponse == limit {
		next = "limit=" + strconv.Itoa(limit) + "&afterId=" + strconv.Itoa(rowId)
	}
	if (afterId - limit) > 0 {
		prev = "limit=" + strconv.Itoa(limit) + "&afterId=" + strconv.Itoa(afterId-limit)
	} else if afterId > 0 {
		prev = "limit=" + strconv.Itoa(limit) + "&afterId=" + strconv.Itoa(0)
	}
	return next, prev
}
