/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package vcss

import (
	"context"
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi/vim25/mo"
	"runtime/debug"
	"time"
)

// VCenterClusterSyncer runs in the background and periodically queries vCenter to get the clusters
// and the hosts associated with the specific clusters. It then queries the HVS database to get the hosts
// registered with HVS belonging to the same cluster. If any host is not registered it registers the new host
// and if a registered host has been deleted from vCenter cluster it is removed from HVS as well.

type VCenterClusterSyncer interface {
	Run() error
	Stop() error
}

var (
	defaultLog = commLog.GetDefaultLogger()
)

func NewVCenterClusterSyncer(cfg config.VCSSConfig, hcConfig domain.HostControllerConfig,
	dataStore *postgres.DataStore, hostTrustManager domain.HostTrustManager) (VCenterClusterSyncer, error) {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:NewVCenterClusterSyncer() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:NewVCenterClusterSyncer() Leaving")

	hostStore := postgres.NewHostStore(dataStore)
	hostStatusStore := postgres.NewHostStatusStore(dataStore)

	flavorStore := postgres.NewFlavorStore(dataStore)
	flavorGroupStore := postgres.NewFlavorGroupStore(dataStore)
	hostCredentialStore := postgres.NewHostCredentialStore(dataStore, hcConfig.DataEncryptionKey)

	ecStore := postgres.NewESXiCLusterStore(dataStore, hcConfig.DataEncryptionKey)

	hostController := controllers.NewHostController(hostStore, hostStatusStore,
		flavorStore, flavorGroupStore, hostCredentialStore,
		hostTrustManager, hcConfig)

	return &vCenterClusterSyncerImpl{
		esxiClusterStore: ecStore,
		hostController:   *hostController,
		cfg:              cfg,
	}, nil
}

type vCenterClusterSyncerImpl struct {
	esxiClusterStore domain.ESXiClusterStore
	hostController   controllers.HostController
	cfg              config.VCSSConfig
	ctx              context.Context
}

func (syncer *vCenterClusterSyncerImpl) Run() error {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:Run() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:Run() Leaving")

	defaultLog.Infof("vcss/vcenter_cluster_syncer:Run() VCSS is starting with refresh period '%s'", syncer.cfg.RefreshPeriod)

	if syncer.cfg.RefreshPeriod == 0 {
		defaultLog.Info("vcss/vcenter_cluster_syncer:Run() The VCSS refresh period is 0 mins. VCSS will now exit")
		return nil
	}

	syncer.ctx = context.Background()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
				defaultLog.Error(string(debug.Stack()))
			}
		}()
		for {
			err := syncer.syncHosts()
			if err != nil {
				defaultLog.Errorf("vcss/vcenter_cluster_syncer:Run() VCSS encountered an error while syncing hosts...\n%+v\n", err)
			}
			select {
			case <-time.After(syncer.cfg.RefreshPeriod):
			case <-syncer.ctx.Done():
				defaultLog.Info("vcss/vcenter_cluster_syncer:Run() The VCSS has been stopped and will now exit")
			}
		}
	}()
	return nil
}

func (syncer *vCenterClusterSyncerImpl) Stop() error {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:Stop() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:Stop() Leaving")

	if syncer.ctx != nil {
		syncer.ctx.Done()
	} else {
		defaultLog.Debug("vcss/vcenter_cluster_syncer:Stop() VCSS is not running")
	}
	return nil
}

func (syncer *vCenterClusterSyncerImpl) syncHosts() error {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:syncHosts() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:syncHosts() Leaving")

	esxiClusters, err := syncer.esxiClusterStore.Search(nil)
	if err != nil {
		return errors.Wrap(err, "vcss/vcenter_cluster_syncer:syncHosts() Error searching for ESXi cluster "+
			"entries in DB")
	}

	for _, cluster := range esxiClusters {
		hostConnector, err := syncer.hostController.HCConfig.HostConnectorProvider.NewHostConnector(cluster.ConnectionString)
		if err != nil {
			defaultLog.WithError(err).Error("vcss/vcenter_cluster_syncer:syncHosts() Error creating host connector instance")
			continue
		}
		hostListFromVcenter, err := hostConnector.GetClusterReference(cluster.ClusterName)
		if err != nil {
			defaultLog.WithError(err).Error("vcss/vcenter_cluster_syncer:syncHosts() Error getting cluster reference from vCenter")
			continue
		}

		hostNamesFromHVS, err := syncer.esxiClusterStore.SearchHosts(cluster.Id)
		if err != nil {
			defaultLog.WithError(err).Error("vcss/vcenter_cluster_syncer:syncHosts() Error searching host from host store")
			continue
		}

		hostsToRegister := getHostsToAdd(hostListFromVcenter, hostNamesFromHVS)
		hostsToRemove := getHostsToRemove(hostListFromVcenter, hostNamesFromHVS)

		defaultLog.Info("vcss/vcenter_cluster_syncer:syncHosts() Syncing registered ESXi hosts with vCenter cluster ...")

		var hostNames []string
		if len(hostsToRegister) > 0 {
			defaultLog.Infof("vcss/vcenter_cluster_syncer:syncHosts() Registering %d new host(s) with HVS ...", len(hostsToRegister))
		}
		for _, host := range hostsToRegister {
			_, _, err := syncer.hostController.CreateHost(hvs.HostCreateRequest{
				HostName:         host.Name,
				Description:      host.Name + " in ESX Cluster " + cluster.ClusterName,
				ConnectionString: fmt.Sprint(cluster.ConnectionString, ";h=", host.Name),
				FlavorgroupNames: nil,
			})
			if err != nil {
				defaultLog.WithError(err).Errorf("vcss/vcenter_cluster_syncer:syncHosts() Error registering host with "+
					"host name %s", host.Name)
			} else {
				hostNames = append(hostNames, host.Name)
				defaultLog.Infof("vcss/vcenter_cluster_syncer:syncHosts() Host with name %s registered to HVS since "+
					"it has been newly added to cluster %s", host.Name, cluster.ClusterName)
			}
		}

		if len(hostNames) > 0 {
			err = syncer.esxiClusterStore.AddHosts(cluster.Id, hostNames)
			if err != nil {
				defaultLog.WithError(err).Error("vcss/vcenter_cluster_syncer:syncHosts() Linking ESXi cluster to" +
					" host failed")
			}
		}

		if len(hostsToRemove) > 0 {
			defaultLog.Infof("vcss/vcenter_cluster_syncer:syncHosts() Deleting %d host(s) from HVS ...", len(hostsToRemove))
		}
		for _, hostName := range hostsToRemove {
			err = syncer.hostController.HStore.DeleteByHostName(hostName)
			if err != nil {
				defaultLog.WithError(err).Errorf("vcss/vcenter_cluster_syncer:syncHosts() Error removing host from DB with "+
					"host name %s", hostName)
			} else {
				defaultLog.Infof("vcss/vcenter_cluster_syncer:syncHosts() Host with name %s removed from DB since "+
					"it is not present in cluster %s", hostName, cluster.ClusterName)
			}
		}
	}
	return nil
}

func getHostsToAdd(hostListFromVcenter []mo.HostSystem, hostNamesFromHVSRecords []string) []mo.HostSystem {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:getHostsToAdd() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:getHostsToAdd() Leaving")

	var hostsToAdd []mo.HostSystem

	for _, host := range hostListFromVcenter {
		hostPresentInHVS := false
		for _, hostName := range hostNamesFromHVSRecords {
			if host.Name == hostName {
				hostPresentInHVS = true
				break
			}
		}
		if !hostPresentInHVS {
			hostsToAdd = append(hostsToAdd, host)
		}
	}
	return hostsToAdd
}

func getHostsToRemove(hostListFromVcenter []mo.HostSystem, hostNamesFromHVSRecords []string) []string {
	defaultLog.Trace("vcss/vcenter_cluster_syncer:getHostsToRemove() Entering")
	defer defaultLog.Trace("vcss/vcenter_cluster_syncer:getHostsToRemove() Leaving")

	var hostsToRemove []string

	for _, hostName := range hostNamesFromHVSRecords {
		hostRemovedFromVcenter := true
		for _, host := range hostListFromVcenter {
			if hostName == host.Name {
				hostRemovedFromVcenter = false
				break
			}
		}
		if hostRemovedFromVcenter {
			hostsToRemove = append(hostsToRemove, hostName)
		}
	}
	return hostsToRemove
}
