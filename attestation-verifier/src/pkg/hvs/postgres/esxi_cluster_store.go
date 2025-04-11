/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package postgres

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"strings"
)

type ESXiClusterStore struct {
	Store *DataStore
	Dek   []byte
}

func NewESXiCLusterStore(store *DataStore, dek []byte) *ESXiClusterStore {
	return &ESXiClusterStore{store, dek}
}

func (e *ESXiClusterStore) Create(esxiCLuster *hvs.ESXiCluster) (*hvs.ESXiCluster, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Create() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Create() Leaving")

	if esxiCLuster.Id == uuid.Nil {
		newUuid, err := uuid.NewRandom()
		if err != nil {
			return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Create() failed to create new UUID")
		}
		esxiCLuster.Id = newUuid
	}

	encCS, err := utils.EncryptString(esxiCLuster.ConnectionString, e.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Create() Failed to encrypt ESXi cluster "+
			"connection string")
	}
	dbESXiCluster := esxiCluster{
		Id:               esxiCLuster.Id,
		ConnectionString: encCS,
		ClusterName:      esxiCLuster.ClusterName,
	}

	if err := e.Store.Db.Create(&dbESXiCluster).Error; err != nil {
		return esxiCLuster, errors.Wrap(err, "postgres/esxi_cluster_store:Create() Failed to create ESXi cluster")
	}

	return esxiCLuster, nil
}

func (e *ESXiClusterStore) Retrieve(id uuid.UUID) (*hvs.ESXiCluster, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Retrieve() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Retrieve() Leaving")

	cluster := hvs.ESXiCluster{}

	row := e.Store.Db.Model(&esxiCluster{}).Where(&esxiCluster{Id: id}).Row()
	err := row.Scan(&cluster.Id, &cluster.ConnectionString, &cluster.ClusterName, &cluster.RowId)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Retrieve() Failed to scan record")
	}

	decryptedCS, err := utils.DecryptString(cluster.ConnectionString, e.Dek)
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Retrieve() Failed to decrypt connection string")
	}

	cluster.ConnectionString = decryptedCS
	return &cluster, nil
}

func (e *ESXiClusterStore) Search(ecFilter *models.ESXiClusterFilterCriteria) ([]hvs.ESXiCluster, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:Search() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Search() Leaving")

	tx := buildESXiClusterSearchQuery(e.Store.Db, ecFilter)
	if tx == nil {
		return nil, errors.New("postgres/esxi_cluster_store:Search() Unexpected Error. Could not build" +
			" a gorm query object.")
	}

	rows, err := tx.Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Search() Failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	clusters := []hvs.ESXiCluster{}
	for rows.Next() {
		cluster := hvs.ESXiCluster{}
		if err := rows.Scan(&cluster.Id, &cluster.ConnectionString, &cluster.ClusterName, &cluster.RowId); err != nil {
			return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Search() Failed to scan record")
		}
		decryptedCS, err := utils.DecryptString(cluster.ConnectionString, e.Dek)
		if err != nil {
			return nil, errors.Wrap(err, "postgres/esxi_cluster_store:Search() Failed to decrypt connection string")
		}

		cluster.ConnectionString = decryptedCS
		clusters = append(clusters, cluster)
	}
	return clusters, nil
}

func (e *ESXiClusterStore) Delete(id uuid.UUID) error {
	defaultLog.Trace("postgres/esxi_cluster_store:Delete() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:Delete() Leaving")

	if err := e.Store.Db.Delete(&esxiCluster{Id: id}).Error; err != nil {
		return errors.Wrap(err, "postgres/esxi_cluster_store:Delete() Failed to delete ESXi cluster")
	}
	return nil
}

// create esxiCluster-Host association
func (e *ESXiClusterStore) AddHosts(esxiClusterId uuid.UUID, hostNames []string) error {
	defaultLog.Trace("postgres/esxi_cluster_store:AddHosts() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:AddHosts() Leaving")

	if esxiClusterId == uuid.Nil {
		return errors.New("postgres/esxi_cluster_store:AddHosts() Must have esxiClusterId " +
			" to associate esxiCluster with the host")
	}

	var echValues []string
	var echValueArgs []interface{}
	for _, name := range hostNames {
		if strings.TrimSpace(name) == "" {
			return errors.New("postgres/esxi_cluster_store:AddHosts() Must have hostname " +
				"to associate esxi Cluster with the host")
		}
		echValues = append(echValues, "(?, ?)")
		echValueArgs = append(echValueArgs, esxiClusterId)
		echValueArgs = append(echValueArgs, name)
	}

	insertQuery := fmt.Sprintf("INSERT INTO esxi_cluster_host VALUES %s", strings.Join(echValues, ","))
	err := e.Store.Db.Model(esxiClusterHost{}).Exec(insertQuery, echValueArgs...).Error
	if err != nil {
		return errors.Wrap(err, "postgres/esxi_cluster_store:AddHosts() Failed to create "+
			"esxi cluster and host association")
	}
	return nil
}

// Search esxiCluster-host association
func (e *ESXiClusterStore) SearchHosts(ecId uuid.UUID) ([]string, error) {
	defaultLog.Trace("postgres/esxi_cluster_store:SearchHosts() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:SearchHosts() Leaving")

	if ecId == uuid.Nil {
		return nil, errors.New("postgres/esxi_cluster_store:SearchHosts() ESXi cluster ID " +
			"must be set to search through esxiCluster host association")
	}

	dbech := esxiClusterHost{
		ClusterID: ecId,
	}

	rows, err := e.Store.Db.Model(&esxiClusterHost{}).Select("hostname").Where(&dbech).Rows()
	if err != nil {
		return nil, errors.Wrap(err, "postgres/esxi_cluster_store:SearchHosts() Failed to retrieve records from db")
	}
	defer func() {
		derr := rows.Close()
		if derr != nil {
			defaultLog.WithError(derr).Error("Error closing rows")
		}
	}()

	hostNames := []string{}
	var name string
	for rows.Next() {
		if err := rows.Scan(&name); err != nil {
			return nil, errors.Wrap(err, "postgres/esxi_cluster_store:SearchHosts() Failed to scan record")
		}
		hostNames = append(hostNames, name)
	}
	return hostNames, nil
}

//Helper function to build the query object for a ESXi cluster search.
func buildESXiClusterSearchQuery(tx *gorm.DB, criteria *models.ESXiClusterFilterCriteria) *gorm.DB {
	defaultLog.Trace("postgres/esxi_cluster_store:buildESXiClusterSearchQuery() Entering")
	defer defaultLog.Trace("postgres/esxi_cluster_store:buildESXiClusterSearchQuery() Leaving")

	if tx == nil {
		return nil
	}

	tx = tx.Model(&esxiCluster{})
	if criteria == nil {
		return tx
	}

	if criteria.Id != uuid.Nil {
		tx = tx.Where("id = ?", criteria.Id)
	} else if criteria.ClusterName != "" {
		tx = tx.Where("cluster_name = ?", criteria.ClusterName)
	}
	if criteria.AfterId > 0 {
		tx = tx.Where("rowid > ?", criteria.AfterId)
	}
	tx = tx.Order("rowid asc")
	if criteria.Limit > 0 {
		tx = tx.Limit(criteria.Limit)
	}

	return tx
}
