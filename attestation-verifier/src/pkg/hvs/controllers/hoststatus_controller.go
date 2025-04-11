/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// HostStatusController contains logic for handling HostStatus API requests
type HostStatusController struct {
	Store domain.HostStatusStore
}

var hostStatusSearchParams = map[string]bool{"id": true, "hostId": true, "hostHardwareId": true, "hostName": true, "hostStatus": true,
	"fromDate": true, "toDate": true, "latestPerHost": true, "numberOfDays": true, "limit": true, "afterId": true}

// Search returns a collection of HostStatus based on HostStatusFilter criteria
func (controller HostStatusController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/hoststatus_controller:Search() Entering")
	defer defaultLog.Trace("controllers/hoststatus_controller:Search() Leaving")

	if err := utils.ValidateQueryParams(r.URL.Query(), hostStatusSearchParams); err != nil {
		secLog.Errorf("controllers/hoststatus_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// get the HostStatusFilterCriteria
	filter, err := getHSFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/hoststatus_controller:Search() %s ", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid filter criteria"}
	}

	hostStatusCollection, err := controller.Store.Search(filter)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/hoststatus_controller:Search() Host Status search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("Host Status search operation failed")
	}

	var next, prev string
	if len(hostStatusCollection) > 0 {
		lastRowId := hostStatusCollection[len(hostStatusCollection)-1].RowId
		next, prev = GetNextAndPrevValues(filter.Limit, filter.AfterId, lastRowId, len(hostStatusCollection))
	}

	hostCollection := hvs.HostStatusCollection{
		HostStatuses: hostStatusCollection, Next: next, Previous: prev,
	}

	secLog.Infof("%s: Return Host Status Search query to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return hostCollection, http.StatusOK, nil
}

// Retrieve returns an existing HostStatus entry from the HostStatusStore
func (controller HostStatusController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/hoststatus_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/hoststatus_controller:Retrieve() Leaving")

	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		defaultLog.WithError(err).WithField("id", mux.Vars(r)["id"]).Warn(
			"controllers/hoststatus_controller:Retrieve() Invalid UUID format of the identifier provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid UUID format of the identifier provided"}
	}

	hostStatus, err := controller.Store.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Warn(
				"controllers/hoststatus_controller:Retrieve() Host Status with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Host Status with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Warn(
				"controllers/hoststatus_controller:Retrieve() failed to retrieve Host Status")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Host Status"}
		}
	}

	return hostStatus, http.StatusOK, nil
}

// getHSFilterCriteria checks for set filter params in the Search request and returns a valid HostStatusFilterCriteria
func getHSFilterCriteria(params url.Values) (*models.HostStatusFilterCriteria, error) {
	defaultLog.Trace("controllers/hoststatus_controller:getHSFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/hoststatus_controller:getHSFilterCriteria() Leaving")

	hfc := models.HostStatusFilterCriteria{}

	// HostStatus ID
	if strings.TrimSpace(params.Get("id")) != "" {
		id, err := uuid.Parse(strings.TrimSpace(params.Get("id")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the HostStatus Identifier specified")
		}
		hfc.Id = id
	}

	//Host ID
	if strings.TrimSpace(params.Get("hostId")) != "" {
		hostId, err := uuid.Parse(strings.TrimSpace(params.Get("hostId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Identifier specified")
		}
		hfc.HostId = hostId
	}

	// Host Hardware UUID
	if strings.TrimSpace(params.Get("hostHardwareId")) != "" {
		hostHardwareId, err := uuid.Parse(strings.TrimSpace(params.Get("hostHardwareId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Hardware Identifier specified")
		}
		hfc.HostHardwareId = hostHardwareId
	}

	// Host Name
	hostName := strings.TrimSpace(params.Get("hostName"))
	if hostName != "" {
		if err := validation.ValidateHostname(hostName); err != nil {
			return nil, errors.Wrap(err, "Valid contents for HostName must be specified")
		}
		hfc.HostName = hostName
	}

	// Host State
	hostState := strings.TrimSpace(params.Get("hostStatus"))
	if hostState != "" {
		if err := validation.ValidateNameString(hostState); err != nil {
			return nil, errors.Wrap(err, "Valid contents for HostStatus must be specified")
		}
		if hvs.GetHostState(hostState) == hvs.HostStateInvalid {
			return nil, errors.New("Valid contents for HostStatus must be specified")
		}
		hfc.HostStatus = hostState
	}

	// fromDate
	fromDate := strings.TrimSpace(params.Get("fromDate"))
	if fromDate != "" {
		pTime, err := utils.ParseDateQueryParam(fromDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid fromDate specified")
		}
		hfc.FromDate = pTime
	}

	// toDate
	toDate := strings.TrimSpace(params.Get("toDate"))
	if toDate != "" {
		pTime, err := utils.ParseDateQueryParam(toDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid toDate specified")
		}
		hfc.ToDate = pTime
	}

	// latestPerHost - defaults to true
	latestPerHost := strings.TrimSpace(strings.ToLower(params.Get("latestPerHost")))
	if latestPerHost != "" {
		lph, err := strconv.ParseBool(latestPerHost)
		if err != nil {
			return nil, errors.Wrap(err, "latestPerHost must be true or false")
		}
		hfc.LatestPerHost = lph
	} else {
		hfc.LatestPerHost = true
	}

	// numberOfDays - defaults to 0
	numberOfDays := strings.TrimSpace(params.Get("numberOfDays"))
	if numberOfDays != "" {
		numDays, err := strconv.Atoi(numberOfDays)
		if err != nil || numDays < 1 || numDays > constants.MaxNumDaysSearchLimit {
			return nil, errors.New("numberOfDays must be an integer between 1 and " + strconv.Itoa(constants.MaxNumDaysSearchLimit))
		}

		// override the existing fromDate/toDate params
		hfc.ToDate = time.Now().UTC()
		hfc.FromDate = hfc.ToDate.AddDate(0, 0, -numDays).UTC()

		hfc.NumberOfDays = numDays
	}

	limit, afterId, err := validation.ValidatePaginationValues(params.Get("limit"), params.Get("afterId"))
	if err != nil {
		return nil, err
	}
	hfc.Limit = limit
	hfc.AfterId = afterId

	return &hfc, nil
}
