/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package commands

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"github.com/pkg/errors"
)

var (
	pcrList  = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}
	pcrBanks = []string{"SHA1", "SHA256"}

	quoteNonce    = []byte("1234567890")
	dummyAssetTag = []byte("1234567890")

	errWrite = ioutil.Discard
)

var tpmTestNames = []string{
	"TPM Active",
	"TPM Ownership",
	"TPM EC",
	"TPM EK",
	"TPM AIK",
	"TPM Signing Key",
	"TPM Binding Key",
	"TPM Quote Generation",
	"Asset Tag",
}

var allFuncs = map[string]func() bool{
	"TPM Active":           tpmActive,
	"TPM Ownership":        tpmOwnership,
	"TPM EC":               tpmEC,
	"TPM EK":               tpmEK,
	"TPM AIK":              tpmAIK,
	"TPM Signing Key":      tpmSigningKey,
	"TPM Binding Key":      tpmBindingKey,
	"TPM Quote Generation": tpmQuote,
	"Asset Tag":            tpmAssetTag,
}

func TPMProviderTest(w io.Writer, tpmSec, aikSec string) error {
	if err := initTPM(); err != nil {
		return errors.Wrap(err, "failed to init tpm provider")
	}
	tpmEnabled, tpmVersion, pcrBanks, err := PlatFormInfoTPM()
	if err != nil {
		return errors.Wrap(err, "failed to check if tpm is enabled")
	}
	errWrite = w
	tpmOwnerSecret = tpmSec
	aikSecret = aikSec
	tpmTestPass := tpmEnabled

	secretbytes, err := crypt.GetRandomBytes(20)
	if err != nil {
		return errors.Wrap(err, "failed to get random bytes")
	}
	signingKeySecret = hex.EncodeToString(secretbytes)
	secretbytes, err = crypt.GetRandomBytes(20)
	if err != nil {
		return errors.Wrap(err, "failed to get random bytes")
	}
	bindingKeySecret = hex.EncodeToString(secretbytes)

	printStr := ""
	indentStr := strings.Repeat(" ", defaultIndent)
	passed := "PASSED\n"
	failed := "FAILED\n"

	for _, k := range tpmTestNames {
		if f, ok := allFuncs[k]; ok {
			printStr += indentStr + k + "..."
			if f() {
				printStr += passed
			} else {
				tpmTestPass = false
				printStr += failed
			}
		}
	}
	tpmTestPass = tpmTestPass && len(pcrBanks) > 0
	// print everything
	fmt.Fprintln(w, "TPM Version: "+tpmVersion)
	if tpmTestPass {
		fmt.Fprintln(w, "TPM Testing...PASSED")
	} else {
		fmt.Fprintln(w, "TPM Testing...FAILED")
	}
	fmt.Fprintf(w, "%s", printStr)
	if len(pcrBanks) > 0 {
		fmt.Fprintln(w, indentStr+"TPM PCR Banks...PASSED")
	}
	fmt.Fprintln(w, indentStr+"Enabled PCR Banks:", strings.Join(pcrBanks, " "))
	return nil
}

func initTPM() error {
	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		return errors.Wrap(err, "failed to create tpm factory")
	}
	tpm, err = tpmFactory.NewTpmProvider()
	if err != nil {
		return errors.Wrap(err, "failed to create tpm provider")
	}
	return nil
}

func tpmActive() bool {
	if tpm.Version() != tpmprovider.V20 {
		fmt.Fprintf(errWrite, "invalid tpm version %d\n", tpm.Version())
		return false
	}
	return true
}

func tpmOwnership() bool {
	err := tpm.TakeOwnership(tpmOwnerSecret)
	if err != nil {
		if !strings.Contains(err.Error(), "0x9A2") {
			fmt.Fprintln(errWrite, "failed to take tpm ownership: "+err.Error())
		}
	}
	owned, err := tpm.IsOwnedWithAuth(tpmOwnerSecret)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to verify tpm ownership: "+err.Error())
	}
	return owned
}

func tpmEC() bool {
	_, err := tpm.NvRead(tpmOwnerSecret, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_RSA_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to read rsa EC from tpm nvram: "+err.Error())
		return false
	}
	_, err = tpm.NvRead(tpmOwnerSecret, tpmprovider.TPM2_RH_OWNER, tpmprovider.NV_IDX_ECC_ENDORSEMENT_CERTIFICATE)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to read ecc EC from tpm nvram: "+err.Error())
		return false
	}
	return true
}

func tpmEK() bool {
	err := tpm.CreateEk(tpmOwnerSecret, tpmprovider.TPM_HANDLE_EK)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to create ek: "+err.Error())
		return false
	}
	return true
}

func tpmAIK() bool {
	err := tpm.CreateAik(tpmOwnerSecret)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to create aik: "+err.Error())
		return false
	}
	_, err = tpm.GetAikBytes()
	if err != nil {
		fmt.Fprintln(errWrite, "failed to retrieve aik: "+err.Error())
		return false
	}
	return true
}

func tpmPrimaryHandle() {
	err := tpm.CreatePrimaryHandle(tpmOwnerSecret, tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		if !strings.Contains(err.Error(), "14c") {
			fmt.Fprintln(errWrite, "failed to create primary handle: "+err.Error())
		}
	}
}

func tpmSigningKey() bool {
	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		fmt.Fprintln(errWrite, "error while checking existence of tpm public key"+err.Error())
	}
	if !exists {
		tpmPrimaryHandle()
	}
	_, err = tpm.CreateSigningKey(aikSecret)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to create signing key: "+err.Error())
		return false
	}
	return true
}

func tpmBindingKey() bool {
	exists, err := tpm.PublicKeyExists(tpmprovider.TPM_HANDLE_PRIMARY)
	if err != nil {
		fmt.Fprintln(errWrite, "error while checking existence of tpm public key"+err.Error())
	}
	if !exists {
		tpmPrimaryHandle()
	}
	_, err = tpm.CreateBindingKey(aikSecret)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to create binding key: "+err.Error())
		return false
	}
	return true
}

func tpmQuote() bool {
	_, err := tpm.GetTpmQuote(quoteNonce, pcrBanks, pcrList)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to create tpm quote: "+err.Error())
		return false
	}
	return true
}

func tpmAssetTag() bool {
	var err error
	// check and clean nv ram if needed
	nvExists, err := tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to check asset tag exist: "+err.Error())
		return false
	}
	if nvExists {
		err = tpm.NvRelease(tpmOwnerSecret, tpmprovider.NV_IDX_ASSET_TAG)
		if err != nil {
			fmt.Fprintln(errWrite, "failed to release asset tag: "+err.Error())
			return false
		}
	}
	err = tpm.NvDefine(tpmOwnerSecret, aikSecret, tpmprovider.NV_IDX_ASSET_TAG, uint16(len(dummyAssetTag)))
	if err != nil {
		fmt.Fprintln(errWrite, "failed to define asset tag: "+err.Error())
		return false
	}
	err = tpm.NvWrite(aikSecret, tpmprovider.NV_IDX_ASSET_TAG, tpmprovider.NV_IDX_ASSET_TAG, dummyAssetTag)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to write asset tag: "+err.Error())
		return false
	}
	nvExists, err = tpm.NvIndexExists(tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to check asset tag exist: "+err.Error())
		return false
	}
	if !nvExists {
		fmt.Fprintln(errWrite, "asset tag is not created")
		return false
	}
	err = tpm.NvRelease(tpmOwnerSecret, tpmprovider.NV_IDX_ASSET_TAG)
	if err != nil {
		fmt.Fprintln(errWrite, "failed to release asset tag: "+err.Error())
		return false
	}
	return true
}
