/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package commands

import (
	"fmt"
	"io"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/hostinfo"

	"github.com/pkg/errors"
)

const defaultIndent = 4

func printWithIndent(w io.Writer, i int, msg string) {
	indentStr := strings.Repeat(" ", i)
	fmt.Fprintln(w, indentStr+msg)
}

func PlatFormInfoTest(w io.Writer) error {
	platformInfoStruct := hostinfo.NewHostInfoParser().Parse()

	defer func() {
		if err := recover(); err == nil {
			fmt.Fprintln(w, "HOST INFO...PASSED")
		}
	}()

	// print general info
	printWithIndent(w, defaultIndent, "OS: "+platformInfoStruct.OSName+" "+platformInfoStruct.OSVersion)
	printWithIndent(w, defaultIndent, "BIOS: "+platformInfoStruct.BiosName+" "+platformInfoStruct.BiosVersion)
	printWithIndent(w, defaultIndent, "CPU ID: "+platformInfoStruct.ProcessorInfo)
	printWithIndent(w, defaultIndent, "System UUID: "+platformInfoStruct.HardwareUUID)

	// print hardware feature
	if platformInfoStruct.HardwareFeatures.TXT.Enabled {
		printWithIndent(w, defaultIndent, "TXT: Enabled")
	} else {
		printWithIndent(w, defaultIndent, "TXT: Disabled")
	}
	if platformInfoStruct.HardwareFeatures.CBNT != nil {
		if platformInfoStruct.HardwareFeatures.CBNT.Enabled {
			printWithIndent(w, defaultIndent, "BootGuard: Enabled")
			printWithIndent(w, defaultIndent, "BootGuard Profile: "+platformInfoStruct.HardwareFeatures.CBNT.Meta.Profile)
		} else {
			printWithIndent(w, defaultIndent, "BootGuard: Disabled")
		}
	}
	if platformInfoStruct.HardwareFeatures.UEFI != nil {
		if platformInfoStruct.HardwareFeatures.UEFI.Enabled {
			printWithIndent(w, defaultIndent, "UEFI: Enabled")
		} else {
			printWithIndent(w, defaultIndent, "UEFI: Disabled")
		}
	}

	if platformInfoStruct.HardwareFeatures.UEFI.Meta.SecureBootEnabled == true {
		printWithIndent(w, defaultIndent, "Secure boot: Enabled")
	} else {
		printWithIndent(w, defaultIndent, "Secure boot: Disabled")
	}

	sgxDiscoveryData, tdxDiscoveryData, _, _, err := utils.GetPlatformData()
	if err != nil {
		if strings.Contains(err.Error(), "SGX Extensions are not supported") {
			printWithIndent(w, defaultIndent, "SGX: Not supported")
		} else {
			printWithIndent(w, defaultIndent, "Failed to get SGX/TDX platform data. "+err.Error())
		}
	} else {
		if sgxDiscoveryData == nil || !sgxDiscoveryData.SgxSupported {
			printWithIndent(w, defaultIndent, "SGX: Not supported")
		} else {
			if sgxDiscoveryData.SgxEnabled {
				printWithIndent(w, defaultIndent, "SGX: Enabled")
			} else {
				printWithIndent(w, defaultIndent, "SGX: Disabled")
			}
		}

		if tdxDiscoveryData == nil || !tdxDiscoveryData.TdxSupported {
			printWithIndent(w, defaultIndent, "TDX: Not supported")
		} else {
			if tdxDiscoveryData.TdxEnabled {
				printWithIndent(w, defaultIndent, "TDX: Enabled")
			} else {
				printWithIndent(w, defaultIndent, "TDX: Disabled")
			}
		}
	}
	return nil
}

func CheckTrustedBoot(w io.Writer) (bool, error) {
	pInfo := hostinfo.NewHostInfoParser().Parse()

	if !pInfo.HardwareFeatures.TPM.Enabled {
		fmt.Fprintln(w, "Trusted Boot...FAILED")
		printWithIndent(w, defaultIndent, "TPM not enabled")
		return false, nil
	}
	var txt, bootGuard, suefi, tboot bool
	txt = pInfo.HardwareFeatures.TXT.Enabled
	tboot = pInfo.TbootInstalled
	if pInfo.HardwareFeatures.CBNT != nil {
		bootGuard = pInfo.HardwareFeatures.CBNT.Enabled
	}
	if pInfo.HardwareFeatures.UEFI != nil {
		suefi = pInfo.HardwareFeatures.UEFI.Enabled
	}
	trustedBootPass := false
	if txt {
		trustedBootPass = tboot || suefi
	} else {
		trustedBootPass = bootGuard && suefi
	}
	var opt []string
	if txt {
		opt = append(opt, "TXT")
	}
	if bootGuard {
		opt = append(opt, "Boot Guard")
	}
	if tboot {
		opt = append(opt, "tboot")
	}
	if suefi {
		opt = append(opt, "SUEFI")
	}
	if trustedBootPass {
		fmt.Fprintln(w, "Trusted Boot...PASSED")
		printWithIndent(w, defaultIndent, "Trusted boot configuration: "+strings.Join(opt, ", "))
	} else {
		fmt.Fprintln(w, "Trusted Boot...FAILED")
		printWithIndent(w, defaultIndent, "Detected configuration is invalid: "+strings.Join(opt, ", "))
	}
	return trustedBootPass, nil
}

func PlatFormInfoTPM() (bool, string, []string, error) {
	pInfo := hostinfo.NewHostInfoParser().Parse()
	if pInfo == nil || pInfo.HardwareFeatures.TPM == nil {
		return false, "", nil, errors.New("Error getting TPM info from host")
	}
	return pInfo.HardwareFeatures.TPM.Enabled, pInfo.HardwareFeatures.TPM.Meta.TPMVersion, []string{"SHA1", "SHA256"}, nil
}
