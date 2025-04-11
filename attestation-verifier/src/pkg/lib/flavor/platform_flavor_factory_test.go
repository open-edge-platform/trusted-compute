/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package flavor

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/types"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/flavor/util"
	hcConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/stretchr/testify/assert"
)

const (
	RHELManifestPath   string = "./test/resources/RHELHostManifest.json"
	TagCertPath        string = "./test/resources/AssetTagpem.Cert"
	GoodSoftwareFlavor string = "./test/resources/SoftwareFlavor.xml"
	BadSoftwareFlavor  string = "./test/resources/BadSoftwareFlavor.xml"

	ESXHostManifestPath        string = "./test/resources/VMWareManifest.json"
	RHELManifestPathWSwFlavors string = "./test/resources/SWManifest.json"

	FlavorTemplatePath string = "./test/resources/TestTemplate.json"
)

var pfutil util.PlatformFlavorUtil
var flavorTemplates []hvs.FlavorTemplate

func getFlavorTemplates(osName string, templatePath string) []hvs.FlavorTemplate {

	var template hvs.FlavorTemplate
	var templates []hvs.FlavorTemplate

	// load hostmanifest
	if templatePath != "" {
		templateFile, _ := os.Open(templatePath)
		templateFileBytes, _ := ioutil.ReadAll(templateFile)
		_ = json.Unmarshal(templateFileBytes, &template)
		templates = append(templates, template)
	}
	return templates
}

// checkIfRequiredFlavorsArePresent is a helper function that ensures expected flavorparts are present in Flavor
func checkIfRequiredFlavorsArePresent(t *testing.T, expFlavorParts []hvs.FlavorPartName, actualFlavorParts []hvs.FlavorPartName) {
	// check if expected flavorparts are present
	for _, expFp := range expFlavorParts {
		fpPresent := false
		for _, actFp := range actualFlavorParts {
			if expFp == actFp {
				fpPresent = true
				break
			}
		}
		assert.True(t, fpPresent, "All expected flavors not present")
	}
	// all good
}

func getSignedFlavor(t *testing.T, pflavor *types.PlatformFlavor, part hvs.FlavorPartName) {
	// Generate Signing Keypair
	sPriKey, _, _ := crypt.CreateSelfSignedCertAndRSAPrivKeys()

	unsignedFlavors, err := (*pflavor).GetFlavorPartRaw(part)
	assert.NoError(t, err, "failed to marshal SignedFlavor")

	signedFlavor, err := pfutil.GetSignedFlavor(&unsignedFlavors[0], sPriKey)

	// Convert SignedFlavor to json
	jsonSf, err := json.Marshal(signedFlavor)
	assert.NoError(t, err, "failed to marshal SignedFlavor")
	assert.NotNil(t, jsonSf, "failed to marshal SignedFlavor")
	t.Log(string(jsonSf))
}

// TestLinuxPlatformFlavorGetFlavorParts validates the GetFlavorPartNames() method implementation of LinuxPlatformFlavor
func TestLinuxPlatformFlavorGetFlavorParts(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := hvs.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)
}

// TestLinuxPlatformFlavorGetSignedPlatformFlavorWithoutAssetTag fetches prepares the SignedFlavor without an asset tag certificate
func TestLinuxPlatformFlavorGetSignedPlatformFlavorWithoutAssetTag(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := hvs.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	// remove Asset Tag from the list of expected flavors
	for i, flavorPart := range expFlavorParts {
		if flavorPart == hvs.FlavorPartAssetTag {
			expFlavorParts = append(expFlavorParts[:i], expFlavorParts[i+1:]...)
		}
	}

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartPlatform)
}

// TestLinuxPlatformFlavorGetSignedPlatformFlavor fetches the Platform flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := hvs.GetFlavorTypes()

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartPlatform)
}

// TestLinuxPlatformFlavorGetSignedOSFlavor fetches the OS flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedOSFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartOs}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()

	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartOs)
}

// TestLinuxPlatformFlavorGetSignedHostUniqueFlavor fetches the Host Unique flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedHostUniqueFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartHostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartHostUnique)
}

// TestLinuxPlatformFlavorGetSignedSoftwareFlavor fetches the Software flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestLinuxPlatformFlavorGetSignedSoftwareFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartSoftware}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPathWSwFlavors, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartSoftware)
}

// TestCreateAssetTagFlavorOnly fetches the ASSET_TAG flavor using
// GetFlavorPartNames() method implementation of LinuxPlatformFlavor
// And fetches the corresponding SignedFlavor
func TestRHELCreateAssetTagFlavorOnly(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartAssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(RHELManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartAssetTag)
}

// TestSoftwareFlavor validates GetSoftwareFlavor()
func TestSoftwareFlavor(t *testing.T) {
	var sf types.SoftwareFlavor
	// load flavor
	softwareFile, _ := os.Open(GoodSoftwareFlavor)
	sfBytes, _ := ioutil.ReadAll(softwareFile)

	sf = types.SoftwareFlavor{
		Measurement: string(sfBytes),
	}
	sfg, err := sf.GetSoftwareFlavor()
	assert.NoError(t, err, "Failed generating software flavor")
	t.Log(sfg)
}

// ---------------------------------------
// ESXPlatformFlavor Tests
// ---------------------------------------

// TestSignedESXPlatformFlavor validates the FlavorParts from an ESXPlatformFlavor
// and generates a Signed Platform Flavor
func TestSignedESXPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartPlatform, hvs.FlavorPartOs, hvs.FlavorPartHostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartPlatform)
}

// TestSignedESXOsFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed OS Flavor
func TestSignedESXOsFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartOs}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartOs)
}

// TestSignedESXHostUniqueFlavor validates the FlavorParts from an ESXPlatformFlavor
// and generates a Signed HostUnique Flavor
func TestSignedESXHostUniqueFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartHostUnique}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartHostUnique)
}

// TestSignedESXAssetTagFlavorFlavor validates the flavorparts from an ESXPlatformFlavor
// and generates a Signed Asset Tag Flavor
func TestSignedESXAssetTagFlavorFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartAssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))

	// get the flavor
	pflavor, err := pffactory.GetPlatformFlavor()
	assert.NoError(t, err, "Error initializing PlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartAssetTag)
}

// TestPlatformFlavorFactory_GetGenericPlatformFlavor attempts to generate a GenericPlatformFlavor from the
// HostManifest and attributeCertificate
func TestPlatformFlavorFactory_GetGenericPlatformFlavor(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// expected FlavorParts
	expFlavorParts := []hvs.FlavorPartName{hvs.FlavorPartAssetTag}

	// load hostManifest and tagCertificate
	hm, tagCert := loadManifestAndTagCert(ESXHostManifestPath, TagCertPath)

	pffactory, err = NewPlatformFlavorProvider(hm, tagCert, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))
	var vendor hcConstants.Vendor
	_ = (&vendor).GetVendorFromOSType(hm.HostInfo.OSType)
	// get the flavor
	pflavor, err := pffactory.GetGenericPlatformFlavor(vendor)
	assert.NoError(t, err, "Error initializing GenericPlatformFlavor")
	pFlavorParts, err := (*pflavor).GetFlavorPartNames()
	assert.NoError(t, err, "Error fetching flavor parts")
	t.Logf("%v", pFlavorParts)

	checkIfRequiredFlavorsArePresent(t, expFlavorParts, pFlavorParts)

	getSignedFlavor(t, pflavor, hvs.FlavorPartAssetTag)
}

func TestPlatformFlavorFactory_GetGenericPlatformFlavorFault(t *testing.T) {
	var pffactory FlavorProvider
	var err error

	// load hostManifest
	hm, _ := loadManifestAndTagCert(ESXHostManifestPath, "")

	pffactory, err = NewPlatformFlavorProvider(hm, nil, getFlavorTemplates(hm.HostInfo.OSName, FlavorTemplatePath))
	var vendor hcConstants.Vendor
	_ = (&vendor).GetVendorFromOSType(hm.HostInfo.OSType)
	// get the flavor
	_, err = pffactory.GetGenericPlatformFlavor(vendor)
	assert.Error(t, err, "Error initializing GenericPlatformFlavor")
}

// NEGATIVE Cases
// Let's enumerate possible scenarios where the flavor genration might fail
// 1. SignedFlavor creation fails due to null PrivateKey
// 2. SignedFlavor creation fails due to invalid PrivateKey
// 3. SignedFlavor creation fails due to null Flavor JSON
func TestFailures4SignFlavor(t *testing.T) {
	var hm hvs.HostManifest
	var tagCert hvs.X509AttributeCertificate
	var sKey *rsa.PrivateKey

	sKey, _, _ = crypt.CreateSelfSignedCertAndRSAPrivKeys()

	// load manifest
	manifestFile, _ := os.Open(RHELManifestPath)
	manifestBytes, _ := ioutil.ReadAll(manifestFile)
	_ = json.Unmarshal(manifestBytes, &hm)

	// load tag cert
	tagCertFile, _ := os.Open(TagCertPath)
	tagCertBytes, _ := ioutil.ReadAll(tagCertFile)
	_ = json.Unmarshal(tagCertBytes, &tagCert)

	tests := []struct {
		name         string
		signingKey   *rsa.PrivateKey
		hostManifest *hvs.HostManifest
	}{
		{
			name: "Nil Signing Key",
		},
		{
			name: "Invalid Signing Key",
		},
		{
			name: "Nil Host Manifest",
		},
	}

	// loop through the tests
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			switch tt.name {
			case "Nil Host Manifest":
				tt.hostManifest = nil
				tt.signingKey = sKey
			case "Nil Signing Key":
				tt.signingKey = nil
				tt.hostManifest = &hm
			case "Invalid Signing Key":
				tt.hostManifest = &hm
				tt.signingKey = &rsa.PrivateKey{
					PublicKey: rsa.PublicKey{
						N: nil,
						E: 0,
					},
					D:      nil,
					Primes: []*big.Int{big.NewInt(int64(55)), big.NewInt(int64(44))},
				}
			}

			pffactory, err := NewPlatformFlavorProvider(tt.hostManifest, nil, nil)

			pflavor, err := pffactory.GetPlatformFlavor()
			// if Nil Host Manifest - we expect this step to fail
			if tt.name == "Nil Host Manifest" {
				assert.Error(t, err, "Nil Host Manifest Did not fail as expected")
			} else {
				assert.NotNil(t, pflavor, "Error initializing PlatformFlavor")

				unsignedPlatformFlavor, _ := (*pflavor).GetFlavorPartRaw(hvs.FlavorPartPlatform)

				// Sign the flavor - if Nil Signed Flavor or Invalid Signing Key we expect this step to fail
				_, err = pfutil.GetSignedFlavor(&unsignedPlatformFlavor[0], tt.signingKey)
				if tt.name == "Nil Signing Key" || tt.name == "Invalid Signing Key" {
					assert.Error(t, err, "Invalid Singing Key Did not fail as expected")
				}
			}
		})
	}
}

// TestSoftwareFlavor_Failure validates GetSoftwareFlavor()
func TestSoftwareFlavor_Failure(t *testing.T) {
	var sf types.SoftwareFlavor
	// load flavor
	softwareFile, _ := os.Open(BadSoftwareFlavor)
	sfBytes, _ := ioutil.ReadAll(softwareFile)

	sf = types.SoftwareFlavor{
		Measurement: string(sfBytes),
	}
	sfg, err := sf.GetSoftwareFlavor()
	assert.Error(t, err, "Error expected for invalid software flavor")
	t.Log(sfg)
}

// loadManifestAndTagCert is a helper function that loads a HostManifest and TagCertificate from files
func loadManifestAndTagCert(hmFilePath string, tcFilePath string) (*hvs.HostManifest, *x509.Certificate) {
	var hm hvs.HostManifest
	var tagCert *x509.Certificate

	// load hostmanifest
	if hmFilePath != "" {
		manifestFile, _ := os.Open(hmFilePath)
		manifestBytes, _ := ioutil.ReadAll(manifestFile)
		_ = json.Unmarshal(manifestBytes, &hm)
	}

	// load tag cert
	if tcFilePath != "" {
		// load tagCert
		// read the test tag cert
		tagCertFile, _ := os.Open(tcFilePath)
		tagCertPathBytes, _ := ioutil.ReadAll(tagCertFile)

		// convert pem to cert
		pemBlock, _ := pem.Decode(tagCertPathBytes)
		tagCert, _ = x509.ParseCertificate(pemBlock.Bytes)
	}

	return &hm, tagCert
}
