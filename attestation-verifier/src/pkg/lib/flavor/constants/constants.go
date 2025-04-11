/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

const (
	OsVMware string = "VMWARE ESXI"
	OsLinux  string = "REDHATENTERPRISE"

	// Software Flavor Prefix
	DefaultSoftwareFlavorPrefix string = "ISecL_Default_Application_Flavor_v"
	DefaultWorkloadFlavorPrefix string = "ISecL_Default_Workload_Flavor_v"

	// TPM
	TPMVersion2 string = "2.0"

	Tpm               = "TPM"
	Txt               = "TXT"
	Cbnt              = "CBNT"
	Uefi              = "UEFI"
	SecureBootEnabled = "SecureBootEnabled"

	IslMeasurementSchema = "lib:wml:measurements:1.0"

	// ESXFlavor
	VMWareComponentName = "Vim25Api.HostTpmSoftwareComponentEventDetails"

	// HostInfo
	PCRBankSeparator = "_"

	// Timestamp format
	FlavorTimestampFormat   = "2006-01-02T15:04:05-0700"
	FlavorWoTimestampFormat = "2006-01-02T15:04:05.999999-07:00"

	//PCR Info
	PCR22  = 22
	SHA256 = "SHA256"
	SHA384 = "SHA384"
	SHA1   = "SHA1"

	//IMA label
	IMA = "Isecl_IMA"
)
