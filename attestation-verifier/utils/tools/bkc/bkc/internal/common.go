/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package commands

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	log "github.com/sirupsen/logrus"
	"strings"
	"unicode"

	"github.com/pkg/errors"
)

// These variables can be used by integrators to override the default
// behavior of event-log parsing.  By default, the file paths are empty
// and the Trust-Agent will attempt to read event logs from /dev/mem.
//
// However, in some environments (ex. embedded linux), /dev/mem may not
// be available.  In these scenarios, an integrator can compile the Trust-Agent
// with go build flags and specify a file containing TCG event-log data.
// For example...
//    env CGO_CFLAGS_ALLOW="-f.*" go build -ldflags "-X intel/isecl/go-trust-agent/v5/eventlog.uefiEventLogFile=/tmp/myuefieventlogs.bin"
var (
	uefiEventLogFile = ""
	txtEventLogFile  = ""
)

const (
	Uint8Size            = 1
	Uint16Size           = 2
	Uint32Size           = 4
	Uint64Size           = 8
	ExtDataElementOffset = 92
	Tpm2FileLength       = 76
	// Uefi Event Info
	UefiBaseOffset = 68
	UefiSizeOffset = 64
	// TXT Heap Base Address and size
	DevMemFilePath    = "/dev/mem"
	TxtHeapBaseOffset = 0xFED30300
	TxtHeapSizeOffset = 0xFED30308
	Tpm2Signature     = "TPM2"
	// 501 Events Info
	Event501       = "0x501"
	TBPolicy       = "tb_policy"
	VMLinuz        = "vmlinuz"
	Initrd         = "initrd"
	AssetTag       = "asset-tag"
	Event501Index0 = 0
	Event501Index1 = 1
	Event501Index2 = 2
	Event501Index3 = 3
	Event501Index4 = 4
	//Application Events Info
	AppEventTypeID = "0x90000001"
	AppEventName   = "APPLICATION_AGENT_MEASUREMENT"
	// Event types
	Event80000001 = 0x80000001
	Event80000002 = 0x80000002
	Event80000007 = 0x80000007
	Event8000000A = 0x8000000A
	Event8000000B = 0x8000000B
	Event8000000C = 0x8000000C
	Event80000010 = 0x80000010
	Event800000E0 = 0x800000E0
	Event00000007 = 0x00000007
	Event00000001 = 0x00000001
	Event00000003 = 0x00000003
	Event00000005 = 0x00000005
	Event0000000A = 0x0000000A
	Event0000000C = 0x0000000C
	Event00000012 = 0x00000012
	Event00000010 = 0x00000010
	Event00000011 = 0x00000011
	EV_IPL        = 0x0000000D
	// SHA Types
	SHA1    = "SHA1"
	SHA256  = "SHA256"
	SHA384  = "SHA384"
	SHA512  = "SHA512"
	SM3_256 = "SM3_256"
	// Algorithm Types
	AlgSHA1          = 0x4
	AlgSHA256        = 0xb
	AlgSHA384        = 0xc
	AlgSHA512        = 0xd
	AlgSM3_256       = 0x12
	NullUnicodePoint = "\u0000"
)

// TcgPcrEventV2 structure represents TCG_PCR_EVENT2 of Intel TXT spec rev16.2
type tcgPcrEventV2 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    tpmlDigestValue
	EventSize uint32
	Event     []uint8
}

// TpmlDigestValue structure represents TPML_DIGEST_VALUES of Intel TXT spec rev16.2
type tpmlDigestValue struct {
	Count   uint32
	Digests []tpmtHA
}

// TpmtHA structure represents TPMT_HA of Intel TXT spec rev16.2
type tpmtHA struct {
	HashAlg    uint16
	DigestData []byte
}

// TcgPcrEventV1 structure represents TCG_PCR_EVENT of Intel TXT spec rev16.2
type tcgPcrEventV1 struct {
	PcrIndex  uint32
	EventType uint32
	Digest    [20]byte
	EventSize uint32
	Event     []uint8
}

// UefiGUID structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type uefiGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

// UefiVariableData structure represents UEFI_GUID of TCG PC Client Platform Firmware Profile spec rev22
type uefiVariableData struct {
	VariableName       uefiGUID
	UnicodeNameLength  uint64
	VariableDataLength uint64
	UnicodeName        []uint16
	VariableData       []int8 // Driver or platform-specific data
}

// PfrEventDataHeader structure represents PFR_EVENT_DATA_HEADER
type pfrEventDataHeader struct { // Description
	Version    uint8  // Version# of PFR_EVENT_DATA structure
	Cpld       uint8  // CPLD# (0-based)
	EventID    uint8  // Event Identifier
	Attribute  uint8  // Extend and String Type information
	Reserved   uint32 // Reserved for future use (set to 0)
	InfoSize   uint32 // P, Size of event information in bytes
	StringSize uint32 // S, Size of event string in bytes
}

// EventNameList - define map for event name
var eventNameList = map[uint32]string{
	0x00000000: "EV_PREBOOT_CERT",
	0x00000001: "EV_POST_CODE",
	0x00000002: "EV_UNUSED",
	0x00000003: "EV_NO_ACTION",
	0x00000004: "EV_SEPARATOR",
	0x00000005: "EV_ACTION",
	0x00000006: "EV_EVENT_TAG",
	0x00000007: "EV_S_CRTM_CONTENTS",
	0x00000008: "EV_S_CRTM_VERSION",
	0x00000009: "EV_CPU_MICROCODE",
	0x0000000A: "EV_PLATFORM_CONFIG_FLAGS",
	0x0000000B: "EV_TABLE_OF_DEVICES",
	0x0000000C: "EV_COMPACT_HASH",
	0x0000000D: "EV_IPL",
	0x0000000E: "EV_IPL_PARTITION_DATA",
	0x0000000F: "EV_NONHOST_CODE",
	0x00000010: "EV_NONHOST_CONFIG",
	0x00000011: "EV_NONHOST_INFO",
	0x00000012: "EV_OMIT_BOOT_DEVICE_EVENTS",
	0x80000000: "EV_EFI_EVENT_BASE",
	0x80000001: "EV_EFI_VARIABLE_DRIVER_CONFIG",
	0x80000002: "EV_EFI_VARIABLE_BOOT",
	0x80000003: "EV_EFI_BOOT_SERVICES_APPLICATION",
	0x80000004: "EV_EFI_BOOT_SERVICES_DRIVER",
	0x80000005: "EV_EFI_RUNTIME_SERVICES_DRIVER",
	0x80000006: "EV_EFI_GPT_EVENT",
	0x80000007: "EV_EFI_ACTION",
	0x80000008: "EV_EFI_PLATFORM_FIRMWARE_BLOB",
	0x80000009: "EV_EFI_HANDOFF_TABLES",
	0x8000000A: "EV_EFI_PLATFORM_FIRMWARE_BLOB2",
	0x8000000B: "EV_EFI_HANDOFF_TABLES2",
	0x8000000C: "EV_EFI_VARIABLE_BOOT2",
	0x80000010: "EV_EFI_HCRTM_EVENT",
	0x800000E0: "EV_EFI_VARIABLE_AUTHORITY",
	0x800000E1: "EV_EFI_SPDM_FIRMWARE_BLOB",
	0x800000E2: "EV_EFI_SPDM_FIRMWARE_CONFIG",
	0x401:      "PCR_MAPPING",
	0x402:      "HASH_START",
	0x403:      "COMBINED_HASH",
	0x404:      "MLE_HASH",
	0x40a:      "BIOSAC_REG_DATA",
	0x40b:      "CPU_SCRTM_STAT",
	0x40c:      "LCP_CONTROL_HASH",
	0x40d:      "ELEMENTS_HASH",
	0x40e:      "STM_HASH",
	0x40f:      "OSSINITDATA_CAP_HASH",
	0x410:      "SINIT_PUBKEY_HASH",
	0x411:      "LCP_HASH",
	0x412:      "LCP_DETAILS_HASH",
	0x413:      "LCP_AUTHORITIES_HASH",
	0x414:      "NV_INFO_HASH",
	0x416:      "EVTYPE_KM_HASH",
	0x417:      "EVTYPE_BPM_HASH",
	0x418:      "EVTYPE_KM_INFO_HASH",
	0x419:      "EVTYPE_BPM_INFO_HASH",
	0x41a:      "EVTYPE_BOOT_POL_HASH",
	0x4ff:      "CAP_VALUE",
}

// ParseTcgSpecEvent - Function to parse and Skip TCG_PCR_EVENT(Intel TXT spec. ver. 16.2) from Event Log Data
func parseTcgSpecEvent(buf *bytes.Buffer, size uint32) (*bytes.Buffer, uint32, error) {
	log.Trace("internal/common:parseTcgSpecEvent() Entering")
	defer log.Trace("internal/common:parseTcgSpecEvent() Leaving")

	tcgPcrEvent := tcgPcrEventV1{}
	err := binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.PcrIndex)
	if err != nil {
		return nil, 0, errors.Wrap(err, "internal/common:parseTcgSpecEvent() There is an error reading TCG_PCR_EVENT PCR Index from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventType)
	if err != nil {
		return nil, 0, errors.Wrap(err, "internal/common:parseTcgSpecEvent() There is an error reading TCG_PCR_EVENT Event Type from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.Digest)
	if err != nil {
		return nil, 0, errors.Wrap(err, "internal/common:parseTcgSpecEvent() There is an error reading TCG_PCR_EVENT Digest from Event Log buffer")
	}

	err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent.EventSize)
	if err != nil {
		return nil, 0, errors.Wrap(err, "internal/common:parseTcgSpecEvent() There is an error reading TCG_PCR_EVENT Event Size from Event Log buffer")
	}

	tcgPcrEvent.Event = buf.Next(int(tcgPcrEvent.EventSize))
	return buf, size - (tcgPcrEvent.EventSize + 32), nil
}

// CreateMeasureLog - Function to create PCR Measured log data for measure-log.json
func createMeasureLog(buf *bytes.Buffer, size uint32, pcrEventLogs []PcrEventLog, txtEnabled bool) ([]PcrEventLog, error) {
	log.Trace("internal/common:createMeasureLog() Entering")
	defer log.Trace("internal/common:createMeasureLog() Leaving")

	tcgPcrEvent2 := tcgPcrEventV2{}
	tpmlDigestValues := tpmlDigestValue{}
	var offset int64
	var err error
	event501Index := 0
	for offset = 0; offset < int64(size); {
		err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.PcrIndex)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:createMeasureLog() There is an error reading TCG_PCR_EVENT2 PCR Index from Event Log buffer")
		}

		offset = offset + Uint32Size
		if tcgPcrEvent2.PcrIndex > 23 || tcgPcrEvent2.PcrIndex < 0 {
			break
		}

		err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventType)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:createMeasureLog() There is an error reading TCG_PCR_EVENT2 Event Type from Event Log buffer")
		}

		offset = offset + Uint32Size
		eventTypeStr := fmt.Sprintf("0x%x", tcgPcrEvent2.EventType)
		err = binary.Read(buf, binary.LittleEndian, &tpmlDigestValues.Count)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:createMeasureLog() There is an error reading TCG_PCR_EVENT2 Digest Count from Event Log buffer")
		}

		offset = offset + Uint32Size
		// From Tpm2.0 spec: https://dox.ipxe.org/Tpm20_8h_source.html#l01081
		// It supports only 5 types of digest algorithm
		if tpmlDigestValues.Count <= 0 || tpmlDigestValues.Count > 5 {
			break
		}

		var hashIndex int
		eventData := make([]TpmEvent, tpmlDigestValues.Count)
		pcr := make([]PcrData, tpmlDigestValues.Count)
		for hashIndex = 0; hashIndex < int(tpmlDigestValues.Count); hashIndex++ {
			var digestSize int
			var algID uint16
			err = binary.Read(buf, binary.LittleEndian, &algID)
			if err != nil {
				return nil, errors.Wrap(err, "internal/common:createMeasureLog() There is an error reading TCG_PCR_EVENT2 Algorithm ID from Event Log buffer")
			}

			offset = offset + Uint16Size
			switch algID {
			case AlgSHA1:
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, sha1.Size, buf)
				pcr[hashIndex].Bank = SHA1
			case AlgSHA256:
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, sha256.Size, buf)
				pcr[hashIndex].Bank = SHA256
			case AlgSHA384:
				digestSize = 48
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, digestSize, buf)
				pcr[hashIndex].Bank = SHA384
			case AlgSHA512:
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, sha512.Size, buf)
				pcr[hashIndex].Bank = SHA512
			case AlgSM3_256:
				digestSize = 32
				eventData[hashIndex].Measurement, offset, buf = getHashData(offset, digestSize, buf)
				pcr[hashIndex].Bank = SM3_256
			}

			eventData[hashIndex].TypeID = eventTypeStr
			pcr[hashIndex].Index = tcgPcrEvent2.PcrIndex
			// Map Event name against the specified types from the TCG PC Client Platform Firmware Profile Specification v1.5
			eventName, ok := eventNameList[tcgPcrEvent2.EventType]
			if ok {
				eventData[hashIndex].TypeName = eventName
			} else {
				// Handling of 501 Events according to spec.
				// The first and second  occurrence of 501 events is tb_policy
				// The third occurrence results in “vmlinuz”.
				// The fourth occurrence results in “initrd”.
				// The fifth occurrence results in “asset-tag”.
				// All other occurrences will be blank.
				if eventTypeStr == Event501 {
					switch event501Index {
					case Event501Index0, Event501Index1:
						eventData[hashIndex].TypeName = TBPolicy
					case Event501Index2:
						eventData[hashIndex].TypeName = VMLinuz
					case Event501Index3:
						eventData[hashIndex].TypeName = Initrd
					case Event501Index4:
						eventData[hashIndex].TypeName = AssetTag
					}
				}
			}

			// After parsing of TPML_DIGEST_VALUES form (Intel TXT spec. ver. 16.2) increment the offset to read the next TCG_PCR_EVENT2
			if hashIndex+1 == int(tpmlDigestValues.Count) {
				err = binary.Read(buf, binary.LittleEndian, &tcgPcrEvent2.EventSize)
				if err != nil {
					return nil, errors.Wrap(err, "internal/common:createMeasureLog() There is an error reading TCG_PCR_EVENT2 Event Size from Event Log buffer")
				}

				offset = offset + Uint32Size
				tcgPcrEvent2.Event = buf.Next(int(tcgPcrEvent2.EventSize))
				offset = offset + int64(tcgPcrEvent2.EventSize)
				if eventTypeStr == Event501 {
					event501Index++
				}
				// Adding eventlog data according to PcrEventLog
				for index := 0; index < int(tpmlDigestValues.Count); index++ {
					var tempPcrEventLog PcrEventLog
					// Handling of Uefi Event Tag according to TCG PC Client Platform Firmware Profile Specification v1.5
					if txtEnabled == false {
						eventData[index].Tags, err = getEventTag(tcgPcrEvent2.EventType, tcgPcrEvent2.Event, tcgPcrEvent2.EventSize, tcgPcrEvent2.PcrIndex)
						if err != nil {
							log.WithError(err).Warnf("internal/common:createMeasureLog() There is an error in getting Event Tag. PcrIndex = %x, EventType = %x", tcgPcrEvent2.PcrIndex, tcgPcrEvent2.EventType)
						}
						var cleanTags []string
						for _, tag := range eventData[index].Tags {
							cleanTags = append(cleanTags, removeUnicode(tag))
						}
						eventData[index].Tags = cleanTags
					} else {
						if eventData[hashIndex].TypeName != "" {
							eventData[index].Tags = append(eventData[hashIndex].Tags, eventData[hashIndex].TypeName)
						}
					}

					tempPcrEventLog.Pcr = pcr[index]
					tempPcrEventLog.TpmEvents = append(tempPcrEventLog.TpmEvents, eventData[index])
					if len(pcrEventLogs) == 0 {
						pcrEventLogs = append(pcrEventLogs, tempPcrEventLog)
					} else {
						var flag = 0
						for i := range pcrEventLogs {
							// Check pcr index and bank if already existing in current array and then add eventlog data in array
							if (pcrEventLogs[i].Pcr.Index == pcr[index].Index) && (pcrEventLogs[i].Pcr.Bank == pcr[index].Bank) {
								pcrEventLogs[i].TpmEvents = append(pcrEventLogs[i].TpmEvents, eventData[index])
								flag = 1
								break
							}
						}

						if flag == 0 {
							pcrEventLogs = append(pcrEventLogs, tempPcrEventLog)
						}
					}
				}
			}
		}
	}

	return pcrEventLogs, nil
}

func removeUnicode(input string) string {
	cleanInput := strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, input)
	return cleanInput
}

// GetHashData - Returns string of hash data, the incremented offset and buffer
func getHashData(offset int64, digestSize int, buf *bytes.Buffer) (string, int64, *bytes.Buffer) {
	log.Trace("internal/common:getHashData() Entering")
	defer log.Trace("internal/common:getHashData() Leaving")

	digest := buf.Next(digestSize)
	offset = offset + int64(digestSize)
	digestStr := hex.EncodeToString(digest)
	return digestStr, offset, buf
}

// GetEventTag - Function to get tag for uefi events
func getEventTag(eventType uint32, eventData []byte, eventSize uint32, pcrIndex uint32) ([]string, error) {
	log.Trace("internal/common:getEventTag() Entering")
	defer log.Trace("internal/common:getEventTag() Leaving")
	// Handling EV_EFI_VARIABLE_DRIVER_CONFIG, EV_EFI_VARIABLE_BOOT, EV_EFI_VARIABLE_BOOT2 and EV_EFI_VARIABLE_AUTHORITY as all
	// These events are associated with UEFI_VARIABLE_DATA
	var err error
	if eventType == Event80000001 || eventType == Event80000002 || eventType == Event8000000C || eventType == Event800000E0 {
		var uefiVarData uefiVariableData
		var unicodeName []byte
		var index, index1 int
		buf := bytes.NewBuffer(eventData)
		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.VariableName)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:getEventTag() There is an error reading Variable Name from TCG_PCR_EVENT2 buffer")
		}

		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.UnicodeNameLength)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:getEventTag() There is an error reading UnicodeName Length from TCG_PCR_EVENT2 buffer")
		}

		err = binary.Read(buf, binary.LittleEndian, &uefiVarData.VariableDataLength)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:getEventTag() There is an error reading VariableData Length from TCG_PCR_EVENT2 buffer")
		}

		// Check whether garbage data is filled in place of event data
		if (uefiVarData.UnicodeNameLength + uefiVarData.VariableDataLength) > uint64(eventSize-32) {
			return nil, errors.Wrap(err, "internal/common:getEventTag() Garbage data is filled in place of event data.")
		}

		unicodeName = buf.Next(int(uefiVarData.UnicodeNameLength * 2))
		runeChar := make([]rune, uefiVarData.UnicodeNameLength)
		for index = 0; index1 < int((uefiVarData.UnicodeNameLength * 2)); index++ {
			runeChar[index] = rune(unicodeName[index1])
			index1 = index1 + 2
		}

		return []string{string(runeChar)}, nil
	}
	//Handling EV_EFI_PLATFORM_FIRMWARE_BLOB2 as it is associated with UEFI_PLATFORM_FIRMWARE_BLOB2
	// 0x8000000B is EV_EFI_HANDOFF_TABLES2 but the description starts from second byte similar to UEFI_PLATFORM_FIRMWARE_BLOB2 so handling here.
	if eventType == Event8000000A || eventType == Event8000000B {
		var blobDescriptionSize uint8
		buf := bytes.NewBuffer(eventData)
		err = binary.Read(buf, binary.LittleEndian, &blobDescriptionSize)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:getEventTag() There is an error reading Blob Description Size from TCG_PCR_EVENT2 buffer")
		}

		blobDesc := buf.Next(int(blobDescriptionSize))
		tagName := fmt.Sprintf("%s", blobDesc)
		return []string{tagName}, nil
	}
	// Handling EV_IPL, EV_POST_CODE, EV_ACTION, EV_EFI_ACTION, EV_PLATFORM_CONFIG_FLAGS, EV_COMPACT_HASH(Only when PCR6),
	// EV_OMIT_BOOT_DEVICE_EVENTS and EV_EFI_HCRTM_EVENT all these events as the event data is a String.
	//
	// EV_S_CRTM_CONTENTS also having descriptive string only in real time. But in spec it is mentioned that this
	// event will have UEFI_PLATFORM_FIRMWARE_BLOB2 data. To make this work handling here.
	//
	// EV_IPL is considered deprecated but captured by EFI in PCRs 8/9, recording grub commmand line arguments
	// and other information.  Add these as tags so they can be verified by "eventlog_includes" and "eventlog_equals"
	// flavor-template rules.
	if eventType == EV_IPL || eventType == Event00000001 || eventType == Event00000005 || eventType == Event80000007 || eventType == Event0000000A || (eventType == Event0000000C && pcrIndex == 0x6) || eventType == Event00000012 || eventType == Event80000010 || eventType == Event00000007 {
		buf := bytes.NewBuffer(eventData)
		postCode := buf.Next(int(eventSize))
		tagName := fmt.Sprintf("%s", postCode)
		//In some cases Event data may have extra bytes along with descriptive string followed by null char. So need to display only the string till null char.
		if strings.Contains(tagName, NullUnicodePoint) {
			nullIndex := strings.Index(tagName, NullUnicodePoint)
			if nullIndex == 0 {
				return nil, nil
			}
			return []string{tagName[:nullIndex]}, nil
		}
		return []string{tagName}, nil
	}
	//Handling EV_NO_ACTION Event. If this Event has the event data as StartupLocality followed by 3, the tag should be "StartupLocality3"
	//Event data has StartupLocality followed by 0, then the tag should be "StartupLocality0"
	if eventType == Event00000003 {
		buf := bytes.NewBuffer(eventData)
		noAction := buf.Next(int(eventSize))
		tagName := fmt.Sprintf("%s", noAction)
		//In some cases Event data may have extra bytes along with descriptive string followed by null char. So need to display only the string till null char.
		if strings.Contains(tagName, NullUnicodePoint) {
			nullIndex := strings.Index(tagName, NullUnicodePoint)
			if nullIndex == 0 {
				return nil, nil
			}
			tagName = fmt.Sprintf("%s%d", tagName[:nullIndex], tagName[nullIndex+1])
			return []string{tagName}, nil
		}
		return []string{tagName}, nil
	}
	// Handling EV_NONHOST_CONFIG and EV_NONHOST_INFO as PFR events as per the design
	if eventType == Event00000010 || eventType == Event00000011 {
		var pfrEventSize uint32
		var pfrHeader pfrEventDataHeader
		// As per PFR TPM Event log Design, following are the information about the valid attribute value.
		// Bit1-0 Extend information
		//	00 Extend whole PFR_EVENT_DATA
		//	01 Extend only PFR_EVENT_DATA.Info
		//	02 Extend only PFR_EVENT_DATA.String
		//	03 Reserved for future use
		// Bit6-2 Reserved for future use (set to 0)
		// Bit-7 String Type: 0/1, ASCII/Unicode String
		// Binary representation of valid PFR attribute values are mentioned below
		// 00000000 - 0x0, 00000001 - 0x1, 00000010 - 0x2, 10000000 - 0x80, 10000001 - 0x81, 10000010 - 0x82
		validPFRAttribute := [6]uint8{0x0, 0x1, 0x2, 0x80, 0x81, 0x82}
		buf := bytes.NewBuffer(eventData)
		err = binary.Read(buf, binary.LittleEndian, &pfrHeader)
		if err != nil {
			return nil, errors.Wrap(err, "internal/common:getEventTag() There is an error reading PFR Header from TCG_PCR_EVENT2 buffer")
		}
		// PFR_EVENT_DATA_HEADER includes four UINT8 and three UINT32 variables. PFR_EVENT_DATA includes PFR_EVENT_DATA_HEADER and InfoSize + StringSize
		pfrEventSize = (Uint8Size * 4) + (Uint32Size * 3) + pfrHeader.InfoSize + pfrHeader.StringSize
		// Checking the event size from event log structure and pfr event size is same or not
		if eventSize != pfrEventSize {
			return nil, nil
		}

		// Checking the PCR index, version and event id are valid as mentioned in HLD
		if (pcrIndex != 0 && pcrIndex != 1 && pcrIndex != 7) || pfrHeader.Version != 0x01 || (pfrHeader.EventID <= 1 || pfrHeader.EventID >= 6) {
			return nil, nil
		}

		// Checking the PFR attribute is valid or not as mentioned in the PFR design
		for index, pfrAttr := range validPFRAttribute {
			if pfrHeader.Attribute == pfrAttr {
				break
			}
			if index == 5 {
				return nil, nil
			}
		}

		if pfrHeader.InfoSize != 0 {
			_ = buf.Next(int(pfrHeader.InfoSize))
		}

		if pfrHeader.StringSize != 0 {
			var tagName string
			pfrString := buf.Next(int(pfrHeader.StringSize))
			if len(pfrString) > 0 {
				tagName = fmt.Sprintf("%s", pfrString)
			}
			// Checking the string is starts with PFR/pfr as mentioned in HLD
			if (pfrString[0] == 'P' && pfrString[1] == 'F' && pfrString[2] == 'R') || (pfrString[0] == 'p' && pfrString[1] == 'f' && pfrString[2] == 'r') {
				return []string{tagName}, nil
			}
		}
	}

	return nil, nil
}
