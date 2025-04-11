/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	commLogMsg "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	hcUtil "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vim25/mo"
	"net/http"
	"net/url"
	"strings"
)

type ESXiClusterController struct {
	ECStore     domain.ESXiClusterStore
	HController HostController
}

func NewESXiClusterController(ec domain.ESXiClusterStore, hc HostController) *ESXiClusterController {
	return &ESXiClusterController{
		ECStore:     ec,
		HController: hc,
	}
}

var esxiClusterSearchParams = map[string]bool{"id": true, "clusterName": true, "afterId": true, "limit": true}

func (controller ESXiClusterController) Create(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Create() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Create() Leaving")

	if r.Header.Get("Content-Type") != consts.HTTPMediaTypeJson {
		return nil, http.StatusUnsupportedMediaType, &commErr.ResourceError{Message: "Invalid Content-Type"}
	}

	if r.ContentLength == 0 {
		secLog.Error("controllers/esxi_cluster_controller:Create() The request body is not provided")
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "The request body is not provided"}
	}

	var reqESXiCluster *hvs.ESXiClusterCreateRequest
	// Decode the incoming json data to note struct
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	err := dec.Decode(&reqESXiCluster)
	if err != nil {
		secLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Create() %s :  Failed to decode"+
			" request body as ESXi cluster type", commLogMsg.InvalidInputBadEncoding)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Unable to decode JSON request body"}
	}

	if err := validateESXiClusterRequest(*reqESXiCluster); err != nil {
		secLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Create() %s Error while validating the ESXi Request parameters", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid request body provided"}
	}

	existingCluster, err := controller.ECStore.Search(&models.ESXiClusterFilterCriteria{
		ClusterName: reqESXiCluster.ClusterName,
	})
	if existingCluster != nil && len(existingCluster) > 0 {
		defaultLog.Warn("Trying to register duplicate ESXi cluster. Skipping the registration for this cluster")
		secLog.WithField("Cluster Name", existingCluster[0].ClusterName).Warningf("%s: Trying to "+
			"register duplicate Cluster from addr: %s", commLogMsg.InvalidInputBadParam, r.RemoteAddr)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "ESXi cluster with the same name already exists"}
	}

	hostInfoList, err := controller.getHostsFromCluster(reqESXiCluster)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/esxi_cluster_controller:Create() Error getting hosts from " +
			"ESXi cluster")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while registering a new ESXi cluster"}
	}

	esxiCluster := &hvs.ESXiCluster{
		ConnectionString: reqESXiCluster.ConnectionString,
		ClusterName:      reqESXiCluster.ClusterName,
	}

	newESXiCluster, err := controller.ECStore.Create(esxiCluster)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/esxi_cluster_controller:Create() ESXi cluster registration failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Error while registering a new ESXi cluster"}
	}

	var hostNames []string
	for _, hostInfo := range hostInfoList {
		description := hostInfo.Name + " in ESX Cluster " + reqESXiCluster.ClusterName

		reqHost := hvs.HostCreateRequest{
			HostName:         hostInfo.Name,
			Description:      description,
			ConnectionString: reqESXiCluster.ConnectionString + ";h=" + hostInfo.Name,
		}
		_, _, err := controller.HController.CreateHost(reqHost)
		if err != nil {
			defaultLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Create() ESXi host registration "+
				"failed for host : %s", hostInfo.Name)
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "ESXi host registration " +
				"failed for host : " + hostInfo.Name}
		}
		hostNames = append(hostNames, hostInfo.Name)
	}
	newESXiCluster.ConnectionString = utils.GetConnectionStringWithoutCredentials(newESXiCluster.ConnectionString)

	err = controller.ECStore.AddHosts(newESXiCluster.Id, hostNames)
	if err != nil {
		defaultLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Create() Linking ESXi cluster to" +
			" host failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Linking ESXi cluster to" +
			" host failed"}
	}

	secLog.WithField("Cluster Name", newESXiCluster.ClusterName).Infof("%s: ESXi cluster registered by: %s",
		commLogMsg.PrivilegeModified, r.RemoteAddr)
	return newESXiCluster, http.StatusCreated, nil
}

func (controller ESXiClusterController) Search(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Search() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Search() Leaving")

	var filter *models.ESXiClusterFilterCriteria = nil
	var err error

	// check for query parameters
	defaultLog.WithField("query", r.URL.Query()).Trace("Query ESXi cluster")

	if err := utils.ValidateQueryParams(r.URL.Query(), esxiClusterSearchParams); err != nil {
		secLog.Errorf("controllers/esxi_cluster_controller:Search() %s", err.Error())
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: err.Error()}
	}

	if filter, err = getECCriteria(r.URL.Query()); err != nil {
		secLog.WithError(err).Errorf("controllers/esxi_cluster_controller:Search() %s", commLogMsg.InvalidInputBadParam)
		return nil, http.StatusBadRequest, &commErr.ResourceError{Message: "Invalid search criteria provided"}
	}

	esxiClusters, err := controller.ECStore.Search(filter)
	if err != nil {
		defaultLog.WithError(err).Error("controllers/esxi_cluster_controller:Search() ESXi cluster search failed")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Unable to search ESXi cluster"}
	}

	for index, cluster := range esxiClusters {
		esxiClusters[index].HostNames, err = controller.ECStore.SearchHosts(cluster.Id)
		if err != nil {
			defaultLog.WithError(err).Error("controllers/esxi_cluster_controller:Search() Failed to retrieve " +
				"host names associated with ESXi cluster")
			return nil, http.StatusInternalServerError, errors.New("controllers/esxi_cluster_controller:" +
				"Search() Failed to retrieve host names associated with ESXi cluster")
		}
		esxiClusters[index].ConnectionString = utils.GetConnectionStringWithoutCredentials(esxiClusters[index].ConnectionString)
	}
	var next, prev string
	if len(esxiClusters) > 0 {
		lastRowId := esxiClusters[len(esxiClusters)-1].RowId
		next, prev = GetNextAndPrevValues(filter.Limit, filter.AfterId, lastRowId, len(esxiClusters))
	}

	esxiClusterCollection := hvs.ESXiClusterCollection{ESXiCluster: esxiClusters, Next: next, Previous: prev}

	secLog.Infof("%s: Return ESXi cluster query result to: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
	return esxiClusterCollection, http.StatusOK, nil
}

func (controller ESXiClusterController) Delete(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Delete() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Delete() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	delESXiCluster, err := controller.ECStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Delete() ESXi cluster with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "ESXi cluster with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Delete() Attempt to delete invalid ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
		}
	}

	hostNames, err := controller.ECStore.SearchHosts(id)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/esxi_cluster_controller:Delete() Failed to get host names associated with ESXi cluster")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
	}

	for _, name := range hostNames {
		var hostFilterCriteria = &models.HostFilterCriteria{NameEqualTo: name}
		hostDetails, err := controller.HController.HStore.Search(hostFilterCriteria, nil)
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Error(
				"controllers/esxi_cluster_controller:Delete() Failed to get hosts associated with ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
		}
		err = controller.HController.HStore.Delete(hostDetails[0].Id)
		if err != nil {
			defaultLog.WithError(err).WithField("id", id).Error(
				"controllers/esxi_cluster_controller:Delete() Failed to delete hosts associated with ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
		}
	}
	if err := controller.ECStore.Delete(id); err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/esxi_cluster_controller:Delete() Failed to delete ESXi cluster")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to delete ESXi cluster"}
	}
	secLog.WithField("Cluster name", delESXiCluster.ClusterName).Infof("ESXi cluster deleted by: %s", r.RemoteAddr)
	return nil, http.StatusNoContent, nil
}

func (controller ESXiClusterController) Retrieve(w http.ResponseWriter, r *http.Request) (interface{}, int, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:Retrieve() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:Retrieve() Leaving")

	id := uuid.MustParse(mux.Vars(r)["id"])

	esxiCluster, err := controller.ECStore.Retrieve(id)
	if err != nil {
		if strings.Contains(err.Error(), commErr.RowsNotFound) {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Retrieve() ESXi cluster with given ID does not exist")
			return nil, http.StatusNotFound, &commErr.ResourceError{Message: "ESXi cluster with given ID does not exist"}
		} else {
			defaultLog.WithError(err).WithField("id", id).Info(
				"controllers/esxi_cluster_controller:Retrieve() Failed to retrieve ESXi cluster")
			return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve ESXi cluster"}
		}
	}

	esxiCluster.HostNames, err = controller.ECStore.SearchHosts(esxiCluster.Id)
	if err != nil {
		defaultLog.WithError(err).WithField("id", id).Error(
			"controllers/esxi_cluster_controller:Retrieve() Failed to retrieve host names associated with the " +
				"cluster")
		return nil, http.StatusInternalServerError, &commErr.ResourceError{Message: "Failed to retrieve host names " +
			"associated with the cluster"}
	}

	esxiCluster.ConnectionString = utils.GetConnectionStringWithoutCredentials(esxiCluster.ConnectionString)

	secLog.WithField("Cluster name", esxiCluster.ClusterName).Infof("ESXi cluster retrieved by: %s", r.RemoteAddr)
	return esxiCluster, http.StatusOK, nil
}

func validateESXiClusterRequest(esxiCluster hvs.ESXiClusterCreateRequest) error {
	defaultLog.Trace("controllers/esxi_cluster_controller:ValidateESXiClusterRequest() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:ValidateESXiClusterRequest() Leaving")

	if strings.TrimSpace(esxiCluster.ClusterName) != "" {
		if err := validation.ValidateStrings([]string{esxiCluster.ClusterName}); err != nil {
			return errors.Wrap(err, "Valid ESXi Cluster Name must be specified")
		}
	} else {
		return errors.New("ESXi Cluster Name must be specified")
	}

	if strings.TrimSpace(esxiCluster.ConnectionString) != "" {
		vc, _ := hcUtil.GetConnectorDetails(esxiCluster.ConnectionString)
		if vc.Vendor != constants.VendorVMware {
			return errors.New("Only VMWARE connection strings are supported for this API")
		}
		if err := utils.ValidateConnectionString(esxiCluster.ConnectionString); err != nil {
			return errors.Wrap(err, "Valid Connection string must be specified")
		}
	} else {
		return errors.New("Connection string must be specified")
	}
	return nil
}

func getECCriteria(params url.Values) (*models.ESXiClusterFilterCriteria, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:ValidateECCriteria() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:ValidateECCriteria() Leaving")

	ecfc := models.ESXiClusterFilterCriteria{}

	if strings.TrimSpace(params.Get("id")) != "" {
		parsedId, err := uuid.Parse(params.Get("id"))
		if err != nil {
			secLog.WithError(err).Error("controllers/esxi_cluster_controller:Search() Invalid UUID provided " +
				"in search criteria")
			return nil, errors.Wrap(err, "Invalid UUID provided in search criteria")
		}
		ecfc.Id = parsedId
	} else if strings.TrimSpace(params.Get("clusterName")) != "" {
		if err := validation.ValidateStrings([]string{params.Get("clusterName")}); err != nil {
			return nil, errors.Wrap(err, "Valid contents for Cluster name must be specified")
		}
		ecfc.ClusterName = params.Get("clusterName")
	}

	limit, afterid, err := validation.ValidatePaginationValues(params.Get("limit"), params.Get("afterId"))
	if err != nil {
		return nil, err
	}
	ecfc.Limit = limit
	ecfc.AfterId = afterid

	return &ecfc, nil
}

func (controller *ESXiClusterController) getHostsFromCluster(reqESXiCluster *hvs.ESXiClusterCreateRequest) ([]mo.HostSystem, error) {
	defaultLog.Trace("controllers/esxi_cluster_controller:getHostsFromCluster() Entering")
	defer defaultLog.Trace("controllers/esxi_cluster_controller:getHostsFromCluster() Leaving")
	hostConnectorFactory, err := controller.HController.HCConfig.HostConnectorProvider.NewHostConnector(reqESXiCluster.ConnectionString)
	if err != nil {
		return nil, errors.Wrap(err, "Error creating host connector instance")
	}
	hostInfoList, err := hostConnectorFactory.GetClusterReference(reqESXiCluster.ClusterName)
	if err != nil {
		return nil, errors.Wrap(err, "Error retrieving host info list from cluster")
	}
	return hostInfoList, err
}
