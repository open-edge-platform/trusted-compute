/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type ReportController struct {
	ReportStore     domain.ReportStore
	HostStore       domain.HostStore
	HostStatusStore domain.HostStatusStore
	HTManager       domain.HostTrustManager
}

func NewReportController(rs domain.ReportStore, hs domain.HostStore, hsts domain.HostStatusStore, ht domain.HostTrustManager) *ReportController {
	return &ReportController{rs, hs, hsts, ht}
}

func (controller ReportController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Create() Entering")
	defer defaultLog.Trace("controllers/report_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/report_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqReportCreateRequest hvs.ReportCreateRequest
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqReportCreateRequest)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:Create() %s :  Failed to decode request body as Report Create Criteria", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateReportCreateCriteria(reqReportCreateRequest); err != nil {
		secLog.WithError(err).Errorf("%s controllers/report_controller:Create() Error validating report create criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Bad input given in input request"}
	}

	requestType := r.URL.Query().Get("process")
	async := false
	if requestType != "" && requestType == "async" {
		async = true
	}
	hvsReport, err := controller.createReport(reqReportCreateRequest, async)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/report_controller:Create() Error while creating report")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if async {
		defaultLog.Debug("controllers/report_controller:Create() Asynchronous request to create a trust report was successfully created")
		return nil, http.StatusCreated, nil
	}

	if hvsReport == nil {
		defaultLog.WithError(err).Error("controllers/report_controller:Create() The report was not created")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while creating report"}
	}

	report := ConvertToReport(hvsReport)
	secLog.WithField("Name", report.HostInfo.HostName).Infof("%s: report created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	return report, http.StatusCreated, nil
}

func (controller ReportController) createReport(rsCriteria hvs.ReportCreateRequest, async bool) (*models.HVSReport, error) {
	defaultLog.Trace("controllers/report_controller:createReport() Entering")
	defer defaultLog.Trace("controllers/report_controller:createReport() Leaving")
	hsCriteria := getHostFilterCriteria(rsCriteria)
	hosts, err := controller.HostStore.Search(&hsCriteria, nil)
	if err != nil {
		return nil, errors.Wrap(err, "Error while searching host")
	}

	if hosts == nil || len(hosts) == 0 {
		return nil, errors.New("Host for given criteria does not exist")
	}

	//Always only one record is returned for the particular criteria
	hostId := hosts[0].Id
	// if async is true, process the request to create the report asynchronously by adding the host to queue
	if async {
		defaultLog.Debugf("controllers/report_controller:createReport() Adding host %s to queue to process request to create sync report", hostId.String())
		verr := controller.HTManager.VerifyHostsAsync([]uuid.UUID{hostId}, true, true)
		if verr != nil {
			defaultLog.WithError(verr).Error("controllers/report_controller:createReport() Failed to add host to FV queue")
			return nil, errors.New("Failed to create async reports")
		}
		return nil, nil
	}

	hvsReport, err := controller.HTManager.VerifyHost(hostId, true, true)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:createReport() Failed to create a trust report, flavor verification failed")
	} else if hvsReport == nil {
		return nil, errors.New("Error while creating a report, no rules to be applied")
	}
	hostStatusCollection, err := controller.HostStatusStore.Search(&models.HostStatusFilterCriteria{
		HostId:        hostId,
		LatestPerHost: true,
		Limit:         1,
	})
	if len(hostStatusCollection) == 0 || hostStatusCollection[0].HostStatusInformation.HostState != hvs.HostStateConnected {
		return nil, errors.New("Host is not in CONNECTED state")
	}

	return hvsReport, nil
}

func (controller ReportController) CreateSaml(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:CreateSaml() Entering")
	defer defaultLog.Trace("controllers/report_controller:CreateSaml() Leaving")

	if r.Header.Get("Content-Type") != constants.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}
	if r.Header.Get("Accept") != constants.HTTPMediaTypeSaml {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{
			Message: "Invalid Accept type",
		}
	}
	if r.ContentLength == 0 {
		secLog.Error("controllers/report_controller:CreateSaml() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqReportCreateRequest hvs.ReportCreateRequest
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqReportCreateRequest)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/report_controller:CreateSaml() %s :  Failed to decode request body as Report Create Criteria", commLogMsg.AppRuntimeErr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateReportCreateCriteria(reqReportCreateRequest); err != nil {
		secLog.WithError(err).Errorf("controllers/report_controller:CreateSaml() %s : Error validating report create criteria", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Bad input given in input request"}
	}

	hvsReport, err := controller.createReport(reqReportCreateRequest, false)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/report_controller:CreateSaml() Error while creating SAML report")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}
	if hvsReport == nil {
		defaultLog.WithError(err).Error("controllers/report_controller:CreateSaml() The report was not created")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while creating report"}
	}
	secLog.WithField("Host Name", hvsReport.TrustReport.HostManifest.HostInfo.HostName).Infof("%s: saml report created by: %s", commLogMsg.PrivilegeModified, r.RemoteAddr)
	w.Header().Set("Content-Type", constants.HTTPMediaTypeSaml)
	return hvsReport.Saml, http.StatusCreated, nil
}

func (controller ReportController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/report_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	hvsReport, err := controller.ReportStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() Report with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "Report with given ID does not exist"}
		} else {
			secLog.WithError(err).WithField("id", id).Info(
				"controllers/report_controller:Retrieve() failed to retrieve Report")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve Report"}
		}
	}

	report := ConvertToReport(hvsReport)
	secLog.WithField("report", report).Infof("%s: Report retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return report, http.StatusOK, nil
}

func (controller ReportController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:Search() Entering")
	defer defaultLog.Trace("controllers/report_controller:Search() Leaving")
	//Search params for reports is same as that of host status APIs
	if err := utils.ValidateQueryParams(r.URL.Query(), hostStatusSearchParams); err != nil {
		secLog.Errorf("controllers/report_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// get the ReportFilterCriteria
	reportFilterCriteria, err := getReportFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/report_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Input given in request"}
	}

	hvsReportCollection, err := controller.ReportStore.Search(reportFilterCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/report_controller:Search() HVSReport search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("HVSReport search operation failed")
	}

	var next, prev string
	if len(hvsReportCollection) > 0 {
		lastRowId := hvsReportCollection[len(hvsReportCollection)-1].RowId
		next, prev = GetNextAndPrevValues(reportFilterCriteria.Limit, reportFilterCriteria.AfterId, lastRowId, len(hvsReportCollection))
	}

	reportCollection := hvs.ReportCollection{
		Reports: []*hvs.Report{}, Next: next, Previous: prev,
	}
	for _, hvsReport := range hvsReportCollection {
		reportCollection.Reports = append(reportCollection.Reports, ConvertToReport(&hvsReport))
	}
	secLog.Infof("%s: Reports searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return reportCollection, http.StatusOK, nil
}

func (controller ReportController) SearchSaml(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/report_controller:SearchSaml() Entering")
	defer defaultLog.Trace("controllers/report_controller:SearchSaml() Leaving")

	if r.Header.Get("Accept") != constants.HTTPMediaTypeSaml {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{
			Message: "Invalid Accept type",
		}
	}

	//Search params for reports is same as that of host status APIs
	if err := utils.ValidateQueryParams(r.URL.Query(), hostStatusSearchParams); err != nil {
		secLog.Errorf("controllers/report_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	// get the ReportFilterCriteria
	reportFilterCriteria, err := getReportFilterCriteria(r.URL.Query())
	if err != nil {
		secLog.WithError(err).Warnf("controllers/report_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid Input given in request"}
	}

	hvsReportCollection, err := controller.ReportStore.Search(reportFilterCriteria)
	if err != nil {
		defaultLog.WithError(err).Warnf("controllers/report_controller:SearchSaml() HVSReport search operation failed")
		return nil, http.StatusInternalServerError, errors.Errorf("HVSReport search operation failed")
	}

	var samlCollection strings.Builder
	for _, hvsReport := range hvsReportCollection {
		samlCollection.WriteString(hvsReport.Saml)
	}

	secLog.Infof("%s: SamlReports searched by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	w.Header().Set("Content-Type", constants.HTTPMediaTypeSaml)
	return samlCollection.String(), http.StatusOK, nil
}

// getReportFilterCriteria checks for set filter params in the Search request and returns a valid ReportFilterCriteria
func getReportFilterCriteria(params url.Values) (*models.ReportFilterCriteria, error) {
	defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Entering")
	defer defaultLog.Trace("controllers/report_controller:getReportFilterCriteria() Leaving")

	rfc := models.ReportFilterCriteria{}

	// Report ID
	if strings.TrimSpace(params.Get("id")) != "" {
		id, err := uuid.Parse(strings.TrimSpace(params.Get("id")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Report Identifier specified")
		}
		rfc.ID = id
	}

	//Host ID
	if strings.TrimSpace(params.Get("hostId")) != "" {
		hostId, err := uuid.Parse(strings.TrimSpace(params.Get("hostId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Identifier specified")
		}
		rfc.HostID = hostId
	}

	// Host Hardware UUID
	if strings.TrimSpace(params.Get("hostHardwareId")) != "" {
		hostHardwareId, err := uuid.Parse(strings.TrimSpace(params.Get("hostHardwareId")))
		if err != nil {
			return nil, errors.New("Invalid UUID format of the Host Hardware Identifier specified")
		}
		rfc.HostHardwareID = hostHardwareId
	}

	// Host Name
	hostName := strings.TrimSpace(params.Get("hostName"))
	if hostName != "" {
		if err := validation.ValidateHostname(hostName); err != nil {
			return nil, errors.Wrap(err, "Valid contents for HostName must be specified")
		}
		rfc.HostName = hostName
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
		rfc.HostStatus = hostState
	}

	// fromDate
	fromDate := strings.TrimSpace(params.Get("fromDate"))
	if fromDate != "" {
		pTime, err := utils.ParseDateQueryParam(fromDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid fromDate specified")
		}
		rfc.FromDate = pTime
	}

	// toDate
	toDate := strings.TrimSpace(params.Get("toDate"))
	if toDate != "" {
		pTime, err := utils.ParseDateQueryParam(toDate)
		if err != nil {
			return nil, errors.Wrap(err, "Invalid toDate specified")
		}
		rfc.ToDate = pTime
	}

	// latestPerHost - defaults to true
	latestPerHost := strings.TrimSpace(strings.ToLower(params.Get("latestPerHost")))
	if latestPerHost != "" {
		lph, err := strconv.ParseBool(latestPerHost)
		if err != nil {
			return nil, errors.Wrap(err, "latestPerHost must be true or false")
		}
		rfc.LatestPerHost = lph
	} else {
		rfc.LatestPerHost = true
	}

	// numberOfDays - defaults to 0
	numberOfDays := strings.TrimSpace(params.Get("numberOfDays"))
	if numberOfDays != "" {
		numDays, err := strconv.Atoi(numberOfDays)
		if err != nil || numDays < 0 || numDays > consts.MaxNumDaysSearchLimit {
			return nil, errors.New("NumberOfDays must be an integer >= 0 and <= 365")
		}
		rfc.NumberOfDays = numDays
	}

	limit, afterId, err := validation.ValidatePaginationValues(params.Get("limit"), params.Get("afterId"))
	if err != nil {
		return nil, err
	}
	rfc.Limit = limit
	rfc.AfterId = afterId

	return &rfc, nil
}

func validateReportCreateCriteria(re hvs.ReportCreateRequest) error {
	defaultLog.Trace("controllers/report_controller:validateReportCreateCriteria() Entering")
	defer defaultLog.Trace("controllers/report_controller:validateReportCreateCriteria() Leaving")

	if re.HostName == "" && re.HostID == uuid.Nil && re.HardwareUUID == uuid.Nil {
		return errors.New("hostName, hostId and hostHardwareUuid must be specified")
	}

	if re.HostName != "" {
		if err := validation.ValidateHostname(re.HostName); err != nil {
			return errors.Wrap(err, "hostName contains invalid characters")
		}
	}
	return nil
}

func ConvertToReport(hvsReport *models.HVSReport) *hvs.Report {
	trustInformation := buildTrustInformation(hvsReport.TrustReport)

	report := hvs.Report{
		ID:               hvsReport.ID,
		HostID:           hvsReport.HostID,
		CreatedAt:        hvsReport.CreatedAt,
		Expiration:       hvsReport.Expiration,
		TrustReport:      hvsReport.TrustReport,
		TrustInformation: *trustInformation,
		HostInfo:         hvsReport.TrustReport.HostManifest.HostInfo,
	}
	return &report
}

func buildTrustInformation(trustReport hvs.TrustReport) *hvs.TrustInformation {

	flavorParts := hvs.GetFlavorTypes()
	flavorsTrustStatus := make(map[hvs.FlavorPartName]hvs.FlavorTrustStatus)
	tr := hvs.NewTrustReport(trustReport)
	for _, flavorPart := range flavorParts {
		if len(tr.GetResultsForMarker(flavorPart.String())) > 0 {
			flavorsTrustStatus[flavorPart] = hvs.FlavorTrustStatus{
				Trust:                tr.IsTrustedForMarker(flavorPart.String()),
				RuleResultCollection: tr.GetResultsForMarker(flavorPart.String()),
			}
		}
	}
	return &hvs.TrustInformation{Overall: tr.IsTrusted(), FlavorTrust: flavorsTrustStatus}
}

func getHostFilterCriteria(rsCriteria hvs.ReportCreateRequest) models.HostFilterCriteria {
	var hsCriteria models.HostFilterCriteria
	if rsCriteria.HostName != "" {
		hsCriteria.NameEqualTo = rsCriteria.HostName
	}
	if rsCriteria.HostID != uuid.Nil {
		hsCriteria.Id = rsCriteria.HostID
	}
	if rsCriteria.HardwareUUID != uuid.Nil {
		hsCriteria.HostHardwareId = rsCriteria.HardwareUUID
	}
	return hsCriteria
}
