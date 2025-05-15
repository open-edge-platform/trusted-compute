/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/tasks"

	"github.com/antchfx/jsonquery"
	"github.com/google/uuid"
	"github.com/jinzhu/copier"
	hvsConstants "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/postgres"
	hvsconfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	hvsModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/upgrades/hvs/db/src/flavor-template/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/upgrades/hvs/db/src/flavor-template/database"
	templateModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/upgrades/hvs/db/src/flavor-template/model"

	// Import driver for GORM
	_ "gorm.io/driver/postgres"
)

// eventIDList - define map for event id
var eventIDList = map[string]string{
	"PCR_MAPPING":          "0x401",
	"HASH_START":           "0x402",
	"COMBINED_HASH":        "0x403",
	"MLE_HASH":             "0x404",
	"BIOSAC_REG_DATA":      "0x40a",
	"CPU_SCRTM_STAT":       "0x40b",
	"LCP_CONTROL_HASH":     "0x40c",
	"ELEMENTS_HASH":        "0x40d",
	"STM_HASH":             "0x40e",
	"OSSINITDATA_CAP_HASH": "0x40f",
	"SINIT_PUBKEY_HASH":    "0x410",
	"LCP_HASH":             "0x411",
	"LCP_DETAILS_HASH":     "0x412",
	"LCP_AUTHORITIES_HASH": "0x413",
	"NV_INFO_HASH":         "0x414",
	"EVTYPE_KM_HASH":       "0x416",
	"EVTYPE_BPM_HASH":      "0x417",
	"EVTYPE_KM_INFO_HASH":  "0x418",
	"EVTYPE_BPM_INFO_HASH": "0x419",
	"EVTYPE_BOOT_POL_HASH": "0x41a",
	"CAP_VALUE":            "0x4ff",
	"tb_policy":            "0x501",
	"vmlinuz":              "0x501",
	"initrd":               "0x501",
	"asset-tag":            "0x501",
}

const (
	//Configuration file path
	ConfigFilePath = "/etc/hvs/"

	// Vendor
	IntelVendor  = "INTEL"
	VmwareVendor = "VMWARE"

	// Flavor
	PlatformFlavor   = "PLATFORM"
	OsFlavor         = "OS"
	HostUniqueFlavor = "HOST_UNIQUE"
	AssetTagFlavor   = "ASSET_TAG"
	SoftwareFlavor   = "SOFTWARE"

	// Hardware
	CbntEnabled  = "cbnt_enabled"
	SuefiEnabled = "suefi_enabled"

	// Flavor template
	FlavorTemplateIDs = "flavor_template_ids"
)

var BuildVersion string

// To map the conditions in the flavor template with old flavor part
var flavorTemplateConditions = map[string]string{"//host_info/tboot_installed//*[text()='true']": "//meta/description/tboot_installed//*[text()='true']",
	"//host_info/hardware_features/UEFI/meta/secure_boot_enabled//*[text()='true']": "//hardware/feature/SUEFI/enabled//*[text()='true']",
	"//host_info/hardware_features/CBNT/enabled//*[text()='true']":                  "//hardware/feature/CBNT/enabled//*[text()='true']",
	"//host_info/os_name//*[text()='RedHatEnterprise']":                             "//meta/vendor//*[text()='INTEL']",
	"//host_info/os_name//*[text()='VMware ESXi']":                                  "//meta/vendor//*[text()='VMWARE']",
	"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='2.0']":           "//meta/description/tpm_version//*[text()='2.0']",
	"//host_info/hardware_features/TPM/meta/tpm_version//*[text()='1.2']":           "//meta/description/tpm_version//*[text()='1.2']"}

// findTemplatesToApply finds the correct templates to apply to convert flavor part
func findTemplatesToApply(oldFlavorPart string, defaultFlavorTemplates []hvsModel.FlavorTemplate) ([]hvsModel.FlavorTemplate, error) {
	var filteredTemplates []hvsModel.FlavorTemplate
	var conditionEval bool

	oldFlavorPartJson, err := jsonquery.Parse(strings.NewReader(oldFlavorPart))
	if err != nil {
		return nil, err
	}

	for _, flavorTemplate := range defaultFlavorTemplates {
		if flavorTemplate.Label == "" {
			continue
		}
		conditionEval = false
		for _, condition := range flavorTemplate.Condition {
			conditionEval = true
			flavorPartCondition := flavorTemplateConditions[condition]
			expectedData, _ := jsonquery.Query(oldFlavorPartJson, flavorPartCondition)
			if expectedData == nil {
				conditionEval = false
				break
			}
		}
		if conditionEval {
			filteredTemplates = append(filteredTemplates, flavorTemplate)
		}
	}

	return filteredTemplates, nil
}

// downloadFlavorsAndTemplates downloads flavor and flavor templates from DB
func downloadFlavorsAndTemplates(cfg *hvsconfig.DBConfig, dataStore *postgres.DataStore) ([]templateModel.SignedFlavors, []hvsModel.FlavorTemplate, error) {

	//Downloading old flavors directly from DB
	signedFlavors, err := database.DownloadOldFlavors(cfg, dataStore.Db)
	if err != nil {
		fmt.Println("Failed to download old flavors")
		return nil, nil, err
	}
	if signedFlavors == nil {
		return nil, nil, nil
	}

	//Downloading Flavor templates
	ftStore := postgres.NewFlavorTemplateStore(dataStore)
	FlavorTemplateFilterCriteria := models.FlavorTemplateFilterCriteria{}
	flavorTemplates, err := ftStore.Search(&FlavorTemplateFilterCriteria)
	if err != nil {
		fmt.Println("Failed to download Flavor templates")
		return nil, nil, err
	}

	return signedFlavors, flavorTemplates, nil
}

// main method implements migration of old format of flavor part to new format
func main() {

	fmt.Println("Starting Flavor conversion tool")

	//Fetching configuration details
	configFile := os.Args[1]
	if configFile == "" {
		configFile = ConfigFilePath
	}
	fmt.Println("Reading config from : " + configFile)
	conf, err := config.LoadConfig(configFile)
	if err != nil {
		fmt.Println("Error in getting DB connection details : ", err)
		os.Exit(1)
	}

	//Assiging signing key file path
	signingKeyFilePath := conf.FlavorSigning.KeyFile

	//Checking database connection establishment
	dataStore, err := database.GetDatabaseConnection(&conf.DB)
	if err != nil {
		fmt.Println("Error in establishing database connection")
		os.Exit(1)
	}

	//Load default templates in Database
	loadDefaultTemplates := &tasks.CreateDefaultFlavorTemplate{
		DBConf:    conf.DB,
		Directory: hvsConstants.DefaultFlavorTemplatesDirectory,
	}
	err = loadDefaultTemplates.Run()
	if err != nil {
		fmt.Println("Error in loading flavor templates : ", err)
		os.Exit(1)
	}

	// Download old flavors and flavor templates from database
	signedFlavors, flavorTemplates, err := downloadFlavorsAndTemplates(&conf.DB, dataStore)
	if err != nil {
		fmt.Println("Error in downloading Flavors/flavor templates : ", err)
		os.Exit(1)
	}
	if signedFlavors == nil {
		fmt.Println("\n No flavors present in database, no flavor conversion required")
		return
	}

	// Get the private key if signing key file path is provided
	flavorSignKey := getPrivateKey(signingKeyFilePath)

	// finding the correct template to apply
	flavor, err := json.Marshal(signedFlavors)
	if err != nil {
		fmt.Println("Error in marshalling the old signed flavors")
		os.Exit(1)
	}

	strFlavor := fmt.Sprintf("%v", string(flavor))
	templates, err := findTemplatesToApply(strFlavor, flavorTemplates)
	if err != nil {
		fmt.Println("No matching flavor templates found to start the conversion")
		os.Exit(1)
	}
	if len(templates) <= 0 {
		fmt.Println("No flavor templates are matched with the old flavor part")
		os.Exit(1)
	}

	fmt.Println("Converting and Updating Flavors back into database")
	newFlavor := make([]hvsModel.Flavor, len(signedFlavors))
	for flavorIndex, flavor := range signedFlavors {

		//Skip converting the flavor if the flavor part is software
		if flavor.Flavor.Meta.Description.FlavorPart == SoftwareFlavor {
			continue
		}

		// Updating meta section
		copier.Copy(&newFlavor[flavorIndex].Meta, &flavor.Flavor.Meta)
		if flavor.Flavor.Meta.Vendor == IntelVendor {
			newFlavor[flavorIndex].Meta.Vendor = constants.VendorIntel
		} else if flavor.Flavor.Meta.Vendor == VmwareVendor {
			newFlavor[flavorIndex].Meta.Vendor = constants.VendorVMware
		} else {
			newFlavor[flavorIndex].Meta.Vendor = constants.VendorUnknown
		}

		// Update description
		var description = make(map[string]interface{})
		description = updateDescription(description, flavor.Flavor.Meta, flavor.Flavor.Hardware)
		newFlavor[flavorIndex].Meta.Description = description

		// Updating BIOS section
		if flavor.Flavor.Bios != nil {
			newFlavor[flavorIndex].Bios = new(hvsModel.Bios)
			copier.Copy(newFlavor[flavorIndex].Bios, flavor.Flavor.Bios)
		}

		// Updating Hardware section
		if flavor.Flavor.Hardware != nil {
			newFlavor[flavorIndex].Hardware = new(hvsModel.Hardware)
			copier.Copy(newFlavor[flavorIndex].Hardware, flavor.Flavor.Hardware)

			// TPM
			newFlavor[flavorIndex].Hardware.Feature.TPM = new(hvsModel.TPM)
			newFlavor[flavorIndex].Hardware.Feature.TPM.Meta.TPMVersion = flavor.Flavor.Hardware.Feature.TPM.Version
			newFlavor[flavorIndex].Hardware.Feature.TPM.Meta.PCRBanks = flavor.Flavor.Hardware.Feature.TPM.PcrBanks

			// CBNT
			if flavor.Flavor.Hardware.Feature.CBNT != nil {
				newFlavor[flavorIndex].Hardware.Feature.CBNT = new(hvsModel.CBNT)
				newFlavor[flavorIndex].Hardware.Feature.CBNT.Meta.Profile = flavor.Flavor.Hardware.Feature.CBNT.Profile
			}

			// UEFI
			if flavor.Flavor.Hardware.Feature.SUEFI != nil {
				newFlavor[flavorIndex].Hardware.Feature.UEFI = new(hvsModel.UEFI)
				newFlavor[flavorIndex].Hardware.Feature.UEFI.Meta.SecureBootEnabled = flavor.Flavor.Hardware.Feature.SUEFI.Enabled
			}
		}

		// Updating external section
		if flavor.Flavor.External != nil {
			newFlavor[flavorIndex].External = new(hvsModel.External)
			copier.Copy(newFlavor[flavorIndex].External, flavor.Flavor.External)
		}

		// Copying the pcrs sections from old flavor part to new flavor part
		if flavor.Flavor.Pcrs != nil {
			var flavorTemplateIDList []uuid.UUID
			for _, template := range templates {
				flavorTemplateIDList = append(flavorTemplateIDList, template.ID)
				flavorname := flavor.Flavor.Meta.Description.FlavorPart
				rules, pcrsmap := getPcrRules(flavorname, template)
				if rules != nil && pcrsmap != nil {
					// Update PCR section
					newFlavor[flavorIndex].Pcrs = updatePcrSection(flavor.Flavor.Pcrs, rules, pcrsmap, flavor.Flavor.Meta.Vendor)
				} else {
					continue
				}
			}
			newFlavor[flavorIndex].Meta.Description[FlavorTemplateIDs] = flavorTemplateIDList
		}

		signedFlavor, err := hvsModel.NewSignedFlavor(&newFlavor[flavorIndex], flavorSignKey)
		if err != nil {
			fmt.Println("Error in getting the signed flavor")
			os.Exit(1)
		}

		err = database.UpdateFlavor(&conf.DB, dataStore.Db, newFlavor[flavorIndex].Meta.ID, newFlavor[flavorIndex], signedFlavor.Signature)
		if err != nil {
			fmt.Println("Error in updating database : ", err)
			os.Exit(1)
		}
	}
	fmt.Println("\nFlavor conversion is successful")
}

// updatePcrSection method is used to update the pcr section in new flavor part
func updatePcrSection(Pcrs map[string]map[string]templateModel.PcrEx, rules []hvsModel.PcrRules, pcrsmap map[int][]string, vendor string) []hvsModel.FlavorPcrs {

	newFlavorPcrs := make([]hvsModel.FlavorPcrs, len(pcrsmap))

	for bank, pcrMap := range Pcrs {
		for index, rule := range rules {
			for mapIndex, templateBanks := range pcrsmap {
				if mapIndex != rule.Pcr.Index {
					continue
				}
				pcrIndex := hvsModel.PcrIndex(mapIndex)
				// check if flavor contains measurements for atleast one of the banks mentioned in the template
				if !containsBank(templateBanks, bank) {
					break
				}
				if expectedPcrEx, ok := pcrMap[pcrIndex.String()]; ok {
					newFlavorPcrs[index].Pcr.Index = mapIndex
					newFlavorPcrs[index].Pcr.Bank = bank
					newFlavorPcrs[index].Measurement = expectedPcrEx.Value
					if rule.PcrMatches != nil {
						newFlavorPcrs[index].PCRMatches = *rule.PcrMatches
					}
					var newTpmEvents []hvsModel.EventLog
					if rule.Pcr.Index == newFlavorPcrs[index].Pcr.Index &&
						rule.EventlogEquals != nil && expectedPcrEx.Event != nil && !reflect.ValueOf(rule.EventlogEquals).IsZero() {
						newFlavorPcrs[index].EventlogEqual = new(hvsModel.EventLogEqual)
						if rule.EventlogEquals.ExcludingTags != nil {
							newFlavorPcrs[index].EventlogEqual.ExcludeTags = rule.EventlogEquals.ExcludingTags
						}
						newTpmEvents = make([]hvsModel.EventLog, len(expectedPcrEx.Event))
						newTpmEvents = updateTpmEvents(expectedPcrEx.Event, newTpmEvents, vendor)
						newFlavorPcrs[index].EventlogEqual.Events = newTpmEvents
						newTpmEvents = nil
					}
					if rule.Pcr.Index == newFlavorPcrs[index].Pcr.Index && rule.EventlogIncludes != nil && expectedPcrEx.Event != nil && !reflect.ValueOf(rule.EventlogIncludes).IsZero() {
						newTpmEvents = make([]hvsModel.EventLog, len(expectedPcrEx.Event))
						newTpmEvents = updateTpmEvents(expectedPcrEx.Event, newTpmEvents, vendor)
						newFlavorPcrs[index].EventlogIncludes = newTpmEvents
						newTpmEvents = nil
					}
				}
			}
		}
	}

	return newFlavorPcrs
}

// getPcrRules method is used to get the pcr rules defined in the flavor template
func getPcrRules(flavorName string, template hvsModel.FlavorTemplate) ([]hvsModel.PcrRules, map[int][]string) {
	pcrsmap := make(map[int][]string)
	var rules []hvsModel.PcrRules

	if flavorName == PlatformFlavor && template.FlavorParts.Platform != nil {
		for _, rules := range template.FlavorParts.Platform.PcrRules {
			pcrsmap[rules.Pcr.Index] = rules.Pcr.Bank
		}
		rules = template.FlavorParts.Platform.PcrRules
		return rules, pcrsmap
	} else if flavorName == OsFlavor && template.FlavorParts.OS != nil {
		for _, rules := range template.FlavorParts.OS.PcrRules {
			pcrsmap[rules.Pcr.Index] = rules.Pcr.Bank
		}
		rules = template.FlavorParts.OS.PcrRules
		return rules, pcrsmap
	} else if flavorName == HostUniqueFlavor && template.FlavorParts.HostUnique != nil {
		for _, rules := range template.FlavorParts.HostUnique.PcrRules {
			pcrsmap[rules.Pcr.Index] = rules.Pcr.Bank
		}
		rules = template.FlavorParts.HostUnique.PcrRules
		return rules, pcrsmap
	}

	return nil, nil
}

// updateTpmEvents method is used to update the tpm events
func updateTpmEvents(expectedPcrEvent []templateModel.EventLog, newTpmEvents []hvsModel.EventLog, vendor string) []hvsModel.EventLog {
	// Updating the old event format into new event format
	for eventIndex, oldEvents := range expectedPcrEvent {
		if vendor == IntelVendor {
			newTpmEvents[eventIndex].TypeName = oldEvents.Label
			newTpmEvents[eventIndex].Tags = append(newTpmEvents[eventIndex].Tags, oldEvents.Label)
			newTpmEvents[eventIndex].Measurement = oldEvents.Value
			newTpmEvents[eventIndex].TypeID = eventIDList[oldEvents.Label]
		} else {
			fmt.Println("UNKNOWN VENDOR - unable to update tpm events")
			os.Exit(1)
		}
	}

	return newTpmEvents
}

// getPrivateKey method is used to get the private key from the inputkeypath if present else generates the newkey
func getPrivateKey(signingKeyFilePath string) *rsa.PrivateKey {

	var flavorSignKey *rsa.PrivateKey

	if signingKeyFilePath == "" {
		fmt.Println("No valid path for getting private key")
	} else {
		var err error
		key, err := crypt.GetPrivateKeyFromPKCS8File(signingKeyFilePath)
		if err != nil {
			fmt.Println("Error getting private key", err)
			os.Exit(1)
		}
		flavorSignKey = key.(*rsa.PrivateKey)
	}

	return flavorSignKey
}

// updateDescription method is used to update the description section in flavor
func updateDescription(description map[string]interface{}, meta templateModel.Meta, hardware *templateModel.Hardware) map[string]interface{} {
	description[hvsModel.TbootInstalled] = meta.Description.TbootInstalled
	description[hvsModel.Label] = meta.Description.Label
	description[hvsModel.FlavorPartDescription] = meta.Description.FlavorPart
	description[hvsModel.Source] = meta.Description.Source

	switch meta.Description.FlavorPart {
	case PlatformFlavor:
		description[hvsModel.BiosName] = meta.Description.BiosName
		description[hvsModel.BiosVersion] = meta.Description.BiosVersion
	case OsFlavor:
		description[hvsModel.OsName] = meta.Description.OsName
		description[hvsModel.OsVersion] = meta.Description.OsVersion
		description[hvsModel.VmmName] = meta.Description.VmmName
		description[hvsModel.VmmVersion] = meta.Description.VmmVersion
		description[hvsModel.TpmVersion] = meta.Description.TpmVersion
	case HostUniqueFlavor:
		description[hvsModel.HardwareUUID] = meta.Description.HardwareUUID
		description[hvsModel.BiosName] = meta.Description.BiosName
		description[hvsModel.BiosVersion] = meta.Description.BiosVersion
		description[hvsModel.OsName] = meta.Description.OsName
		description[hvsModel.OsVersion] = meta.Description.OsVersion
		description[hvsModel.TpmVersion] = meta.Description.TpmVersion
	case AssetTagFlavor:
		description[hvsModel.HardwareUUID] = meta.Description.HardwareUUID
		description[hvsModel.TpmVersion] = meta.Description.TpmVersion
	}

	if hardware != nil {
		description[hvsModel.TpmVersion] = hardware.Feature.TPM.Version
		if hardware.Feature.CBNT != nil && hardware.Feature.CBNT.Enabled {
			description[CbntEnabled] = true
		} else if hardware.Feature.SUEFI != nil && hardware.Feature.SUEFI.Enabled {
			description[SuefiEnabled] = true
		}
	}

	return description
}

// containsBank is used to check if a particular PCRbank is among one of the banks listed in the template
func containsBank(pcrBanks []string, pcrBank string) bool {
	for _, bank := range pcrBanks {
		if hvsModel.SHAAlgorithm(pcrBank) == hvsModel.SHAAlgorithm(bank) {
			return true
		}
	}
	return false
}
