/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

type HardwareFeature struct {
	Enabled bool `json:"enabled,string"`
}

type CBNT struct {
	HardwareFeature
	Meta struct {
		Profile string `json:"profile"`
		MSR     string `json:"msr"`
	} `json:"meta"`
}

type TPM struct {
	HardwareFeature
	Meta struct {
		TPMVersion string `json:"tpm_version"`
	} `json:"meta"`
}

type UEFI struct {
	HardwareFeature
	Meta struct {
		SecureBootEnabled bool `json:"secure_boot_enabled"`
	} `json:"meta"`
}

type HostInfo struct {
	OSName              string           `json:"os_name"`
	OSVersion           string           `json:"os_version"`
	OSType              string           `json:"os_type"`
	BiosVersion         string           `json:"bios_version"`
	VMMName             string           `json:"vmm_name"`
	VMMVersion          string           `json:"vmm_version"`
	ProcessorInfo       string           `json:"processor_info"`
	HostName            string           `json:"host_name"`
	BiosName            string           `json:"bios_name"`
	HardwareUUID        string           `json:"hardware_uuid"`
	ProcessorFlags      string           `json:"process_flags"`
	NumberOfSockets     int              `json:"no_of_sockets,string"`
	TbootInstalled      bool             `json:"tboot_installed,string"`
	IsDockerEnvironment bool             `json:"is_docker_env,string"`
	HardwareFeatures    HardwareFeatures `json:"hardware_features"`
	InstalledComponents []string         `json:"installed_components"`
}

type HardwareFeatures struct {
	TXT  *HardwareFeature `json:"TXT,omitempty"`
	TPM  *TPM             `json:"TPM,omitempty"`
	CBNT *CBNT            `json:"CBNT,omitempty"`
	UEFI *UEFI            `json:"UEFI,omitempty"`
	PFR  *HardwareFeature `json:"PFR,omitempty"`
	BMC  *HardwareFeature `json:"BMC,omitempty"`
}

type OSType string

const (
	OsTypeLinux   = "linux"
	OsTypeVMWare  = "vmware"
	OsTypeWindows = "windows"
)

type OsName string

const (
	OsWindows       OsName = "WINDOWS"
	OsWindows2k16   OsName = "MICROSOFT WINDOWS SERVER 2016 STANDARD"
	OsWindows2k16dc OsName = "MICROSOFT WINDOWS SERVER 2016 DATACENTER"
	OsVMware        OsName = "VMWARE ESXI"
)

func (on OsName) String() string {
	return string(on)
}

type HostComponent string

const (
	HostComponentTagent  HostComponent = "tagent"
	HostComponentWlagent HostComponent = "wlagent"
)

func (hc HostComponent) String() string {
	return string(hc)
}
