/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package mocks

import (
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	commErr "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/err"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

var (
	esxiCluster1 = `{"id":"40c6ec42-ee9a-4d8a-842b-cdcd0fefa9c0", 
				"connection_string" :" https://ip1.com:443/sdk;u=username;p=password", "cluster_name" : "Cluster 1"}`
	esxiCluster2 = `{"id":"f3c6a763-51cd-436c-a828-c2ce6964c823", 
				"connection_string" :" https://ip2.com:443/sdk;u=username;p=password", "cluster_name" : "Cluster 2"}`
	esxiCluster3 = `{"id":"a3c6a763-51cd-436c-a828-c2ce6964c823", 
				"connection_string" :" https://ip2.com:443/sdk;u=username;p=password", "cluster_name" : "Cluster 3"}`
	esxiCluster4 = `{"id":"b3c6a763-51cd-436c-a828-c2ce6964c823", 
				"connection_string" :" https://ip2.com:443/sdk;u=username;p=password", "cluster_name" : "Cluster 4"}`
)

type MockESXiClusterStore struct {
	ESXiClusterStore []hvs.ESXiCluster
}

// Retrieve returns ESXi Cluster
func (store *MockESXiClusterStore) Retrieve(id uuid.UUID) (*hvs.ESXiCluster, error) {
	for _, ec := range store.ESXiClusterStore {
		if ec.Id == id {
			return &ec, nil
		}
	}
	return nil, errors.New(commErr.RowsNotFound)
}

// Delete deletes Esxi cluster from the store
func (store *MockESXiClusterStore) Delete(esxiClusterId uuid.UUID) error {
	for _, ec := range store.ESXiClusterStore {
		if ec.Id == esxiClusterId {
			return nil
		}
	}
	return errors.New(commErr.RowsNotFound)
}

// Search returns a filtered list of ESXi clusters as per the provided ESXiClusterFilterCriteria
func (store *MockESXiClusterStore) Search(criteria *models.ESXiClusterFilterCriteria) ([]hvs.ESXiCluster, error) {

	var ecFiltered []hvs.ESXiCluster
	// ESXi cluster ID filter
	if criteria.Limit == 1 || criteria.AfterId == 1 {
		return store.ESXiClusterStore[:1], nil
	} else if criteria.Id != uuid.Nil {
		for _, ec := range store.ESXiClusterStore {
			if ec.Id == criteria.Id {
				ecFiltered = append(ecFiltered, ec)
			}
		}
	} else if criteria.ClusterName != "" {
		for _, ec := range store.ESXiClusterStore {
			if strings.ToLower(ec.ClusterName) == strings.ToLower(criteria.ClusterName) {
				ecFiltered = append(ecFiltered, ec)
			}
		}
	} else {
		return store.ESXiClusterStore, nil
	}

	return ecFiltered, nil
}

// Create inserts a ESXi cluster
func (store *MockESXiClusterStore) Create(ec *hvs.ESXiCluster) (*hvs.ESXiCluster, error) {
	store.ESXiClusterStore = append(store.ESXiClusterStore, *ec)
	return ec, nil
}

func (store *MockESXiClusterStore) AddHosts(esxiClusterId uuid.UUID, hostName []string) error {
	//TODO Implement mock for AddHosts
	return nil
}

func (store *MockESXiClusterStore) SearchHosts(clusterId uuid.UUID) ([]string, error) {
	//TODO Implement mock for SearchHosts
	if clusterId == uuid.MustParse("a3c6a763-51cd-436c-a828-c2ce6964c823") {
		return []string{"Search_Error"}, nil
	} else if clusterId == uuid.MustParse("b3c6a763-51cd-436c-a828-c2ce6964c823") {
		return nil, errors.New("Error in retrieving hosts")
	}
	return []string{"localhost1"}, nil
}

// NewFakeESXiClusterStore loads dummy data into MockESXiClusterStore
func NewFakeESXiClusterStore() *MockESXiClusterStore {
	store := &MockESXiClusterStore{}

	// unmarshal the fixed ESXi cluster
	var ec1, ec2, ec3, ec4 hvs.ESXiCluster
	err := json.Unmarshal([]byte(esxiCluster1), &ec1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	err = json.Unmarshal([]byte(esxiCluster2), &ec2)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	err = json.Unmarshal([]byte(esxiCluster3), &ec3)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	err = json.Unmarshal([]byte(esxiCluster4), &ec4)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	// add to store
	_, err = store.Create(&ec1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}
	_, err = store.Create(&ec2)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}
	_, err = store.Create(&ec3)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}
	_, err = store.Create(&ec4)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}
	return store
}

// NewFakeESXiClusterStore loads dummy data into MockESXiClusterStore
func NewValidFakeESXiClusterStore() *MockESXiClusterStore {
	store := &MockESXiClusterStore{}

	// unmarshal the fixed ESXi cluster
	var ec1, ec2 hvs.ESXiCluster
	err := json.Unmarshal([]byte(esxiCluster1), &ec1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}
	err = json.Unmarshal([]byte(esxiCluster2), &ec2)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating Flavor")
	}

	// add to store
	_, err = store.Create(&ec1)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}
	_, err = store.Create(&ec2)
	if err != nil {
		defaultLog.WithError(err).Errorf("Error creating ESXI cluster")
	}

	return store
}
