/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hostinfo

// go build -ldflags "-X intel-secl/hostinfo.smbiosFile=/tmp/dmi.bin" main.go

var (
	smbiosFile         = "/sys/firmware/dmi/tables/DMI"
	osReleaseFile      = "/etc/os-release"
	msrFile            = "/dev/cpu/0/msr"
	tpm2AcpiFile       = "/sys/firmware/acpi/tables/TPM2"
	hostNameFile       = "/etc/hostname"
	isDockerFile       = "/.dockerenv"
	isOCIContainerFile = "/.container-env"
	isEFIBootFile      = "/sys/firmware/efi"
	tpmDeviceFile      = "/dev/tpm0"
	secureBootFile     = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
)
