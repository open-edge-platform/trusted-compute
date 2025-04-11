/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package vmware

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/pkg/errors"
	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/session"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

var log = commLog.GetDefaultLogger()

type VMWareClient interface {
	GetHostInfo() (taModel.HostInfo, error)
	GetTPMAttestationReport() (*types.QueryTpmAttestationReportResponse, error)
	GetVmwareClusterReference(string) ([]mo.HostSystem, error)
}

const (
	HOST_SYSTEM_PROPERTY    = "HostSystem"
	CLUSTER_SYSTEM_PROPERTY = "ClusterComputeResource"
)

func NewVMwareClient(vcenterApiUrl *url.URL, vcenterUserName, vcenterPassword, hostName string, trustedCaCerts []x509.Certificate) (VMWareClient, error) {

	vmwareClient := vmwareClient{
		BaseURL:         vcenterApiUrl,
		HostName:        hostName,
		vCenterUsername: vcenterUserName,
		vCenterPassword: vcenterPassword,
		TrustedCaCerts:  trustedCaCerts,
	}
	//Set username and password in the same URL struct
	vmwareClient.BaseURL.User = url.UserPassword(vmwareClient.vCenterUsername, vmwareClient.vCenterPassword)

	ctx, _ := context.WithCancel(context.Background())
	vmwareClient.Context = ctx
	if hostName != "" {
		host, vCenterClient, err := getVmwareHostReference(&vmwareClient)
		if err != nil {
			return nil, errors.Wrap(err, "vmware/client:NewVMwareClient() Error creating Vmware client")
		}
		if host.Config == nil {
			return nil, errors.New("vmware/client:NewVMwareClient() Unable to connect to Vmware host : " + hostName)
		}

		vmwareClient.hostReference = host
		vmwareClient.vCenterClient = vCenterClient
	}

	return &vmwareClient, nil
}

type vmwareClient struct {
	BaseURL         *url.URL
	HostName        string
	vCenterUsername string
	vCenterPassword string
	TrustedCaCerts  []x509.Certificate
	hostReference   mo.HostSystem
	vCenterClient   *govmomi.Client
	Context         context.Context
}

func (vc *vmwareClient) GetHostInfo() (taModel.HostInfo, error) {

	log.Trace("vmware/client:GetHostInfo() Entering ")
	defer log.Trace("vmware/client:GetHostInfo() Leaving ")
	var hostInfo taModel.HostInfo

	vcenterVersion := vc.vCenterClient.ServiceContent.About.Version
	hostInfo.HostName = vc.hostReference.Name
	hostInfo.VMMName = vc.hostReference.Config.Product.Name
	hostInfo.OSName = vc.hostReference.Config.Product.Name
	hostInfo.OSVersion = vc.hostReference.Config.Product.Version
	hostInfo.OSType = taModel.OsTypeVMWare
	hostInfo.VMMVersion = vc.hostReference.Config.Product.Build
	hostInfo.BiosName = vc.hostReference.Hardware.SystemInfo.Vendor
	hostInfo.BiosVersion = vc.hostReference.Hardware.BiosInfo.BiosVersion
	hostInfo.NumberOfSockets = int(vc.hostReference.Hardware.CpuInfo.NumCpuPackages)
	hostInfo.ProcessorInfo = vc.hostReference.Summary.MaxEVCModeKey
	hostInfo.HardwareUUID = strings.ToUpper(vc.hostReference.Hardware.SystemInfo.Uuid)
	hostInfo.HardwareFeatures.TPM = &taModel.TPM{}
	hostInfo.HardwareFeatures.TPM.Enabled = false
	if vc.hostReference.Capability.TpmSupported != nil {
		hostInfo.HardwareFeatures.TPM.Enabled = true
	}
	if strings.Contains(vcenterVersion, "6.5") && hostInfo.HardwareFeatures.TPM.Enabled {
		hostInfo.HardwareFeatures.TPM.Meta.TPMVersion = "1.2"
		attestationReport, err := vc.GetTPMAttestationReport()
		if err != nil {
			return taModel.HostInfo{}, errors.Wrap(err, "vmware/client:GetHostInfo() Error getting attestation"+
				"report from vcenter api")
		}
		if attestationReport.Returnval.TpmLogReliable {
			hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: true}
		} else {
			hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: false}
		}
	} else {
		hostInfo.HardwareFeatures.TPM.Meta.TPMVersion = vc.hostReference.Capability.TpmVersion
		txtEnabled := false
		if vc.hostReference.Capability.TxtEnabled != nil && *vc.hostReference.Capability.TxtEnabled == true {
			txtEnabled = true
		}
		hostInfo.HardwareFeatures.TXT = &taModel.HardwareFeature{Enabled: txtEnabled}
	}
	return hostInfo, nil
}

func (vc *vmwareClient) GetTPMAttestationReport() (*types.QueryTpmAttestationReportResponse, error) {

	log.Trace("vmware/client:GetTPMAttestationReport() Entering ")
	defer log.Trace("vmware/client:GetTPMAttestationReport() Leaving ")

	query := types.QueryTpmAttestationReport{This: vc.hostReference.Reference()}
	attestationReport, err := methods.QueryTpmAttestationReport(vc.Context, vc.vCenterClient.RoundTripper, &query)
	if err != nil {
		return attestationReport, err
	}
	return attestationReport, nil
}

func getVmwareHostReference(vc *vmwareClient) (mo.HostSystem, *govmomi.Client, error) {
	log.Trace("vmware/client:getVmwareHostReference() Entering ")
	defer log.Trace("vmware/client:getVmwareHostReference() Leaving ")

	vmwareClient, err := getGovmomiClient(vc)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, err
	}
	viewManager := view.NewManager(vmwareClient.Client)
	defer func() {
		_, derr := viewManager.Destroy(vc.Context)
		if derr != nil {
			log.WithError(derr).Error("Error destroying context")
		}
	}()
	viewer, err := viewManager.CreateContainerView(vc.Context, vmwareClient.ServiceContent.RootFolder,
		[]string{HOST_SYSTEM_PROPERTY}, true)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, errors.Wrap(err, "vmware/client:getVmwareHostReference() Error "+
			"creating container view from client")
	}
	defer func() {
		derr := viewer.Destroy(vc.Context)
		if derr != nil {
			log.WithError(derr).Error("Error destroying context")
		}
	}()

	var hs []mo.HostSystem

	err = viewer.Retrieve(vc.Context, []string{HOST_SYSTEM_PROPERTY}, []string{"name", "summary", "config",
		"capability", "hardware", "runtime", "parent"}, &hs)
	if err != nil {
		return mo.HostSystem{}, vmwareClient, err
	}

	for _, host := range hs {
		if host.Name == vc.HostName {
			return host, vmwareClient, nil
		}
	}

	return mo.HostSystem{}, vmwareClient, errors.New("vmware/client:getVmwareHostReference() No host with " +
		"hostname " + vc.HostName + " found in cluster")
}

func (vc *vmwareClient) GetVmwareClusterReference(clusterName string) ([]mo.HostSystem, error) {
	log.Trace("vmware/client:GetVmwareClusterReference() Entering ")
	defer log.Trace("vmware/client:GetVmwareClusterReference() Leaving ")

	vmwareClient, err := getGovmomiClient(vc)
	if err != nil {
		return nil, errors.Wrap(err, "vmware/client:getVmwareClusterReference() Error "+
			"creating vsphere client")
	}
	viewManager := view.NewManager(vmwareClient.Client)
	defer func() {
		_, derr := viewManager.Destroy(vc.Context)
		if derr != nil {
			log.WithError(derr).Error("Error destroying context")
		}
	}()
	viewer, err := viewManager.CreateContainerView(vc.Context, vmwareClient.ServiceContent.RootFolder,
		[]string{CLUSTER_SYSTEM_PROPERTY}, true)
	if err != nil {
		return nil, errors.Wrap(err, "vmware/client:getVmwareClusterReference() Error "+
			"creating container view from client")
	}
	defer func() {
		derr := viewer.Destroy(vc.Context)
		if derr != nil {
			log.WithError(derr).Error("Error destroying context")
		}
	}()
	var ccr []mo.ClusterComputeResource

	err = viewer.Retrieve(vc.Context, []string{CLUSTER_SYSTEM_PROPERTY}, []string{"name", "host"}, &ccr)
	if err != nil {
		return nil, errors.Wrap(err, "vmware/client:getVmwareClusterReference() Error "+
			"getting cluster properties")
	}

	var hostInfo []mo.HostSystem
	for _, cluster := range ccr {
		if cluster.Name == clusterName {
			err := vmwareClient.Retrieve(vc.Context, cluster.Host, []string{"name", "summary", "config",
				"capability", "hardware", "runtime", "parent"}, &hostInfo)
			if err != nil {
				return nil, errors.Wrap(err, "vmware/client:getVmwareClusterReference() Error "+
					"getting hosts from cluster")
			}
		}
	}

	return hostInfo, nil
}

func getGovmomiClient(vc *vmwareClient) (*govmomi.Client, error) {
	log.Trace("vmware/client:getGovmomiClient() Entering ")
	defer log.Trace("vmware/client:getGovmomiClient() Leaving ")

	soapClient := soap.NewClient(vc.BaseURL, false)
	soapClient.DefaultTransport().TLSClientConfig.RootCAs = clients.GetCertPool(vc.TrustedCaCerts)

	vimClient, err := vim25.NewClient(vc.Context, soapClient)
	if err != nil {
		return &govmomi.Client{}, errors.Wrap(err, "vmware/client:getGovmomiClient() Error "+
			"creating vim25 client")
	}
	vmwareClient := &govmomi.Client{
		Client:         vimClient,
		SessionManager: session.NewManager(vimClient),
	}

	// Only login if the URL contains user information.
	if vc.BaseURL.User != nil || vc.BaseURL.User.String() != "" {
		err = vmwareClient.Login(vc.Context, vc.BaseURL.User)
		if err != nil {
			return vmwareClient, errors.Wrap(err, "vmware/client:getGovmomiClient() Error "+
				"creating vcenter session")
		}
	}
	return vmwareClient, nil
}
