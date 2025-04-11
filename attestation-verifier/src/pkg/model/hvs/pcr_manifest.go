/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package hvs

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"unsafe"

	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

const (
	StartupLocalityTag   = "StartupLocality3"
	StartupLocalityEvent = "EV_NO_ACTION"
)

const (
	PCR_INDEX_PREFIX = "pcr_"
)

const (
	IMA_NG_TEMPLATE  = "ima-ng"
	IMA_SIG_TEMPLATE = "ima-sig"
	IMA_TEMPLATE     = "ima"
)

const (
	SUFFIX_SHA1     = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
	SUFFIX_SHA256   = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
	SHA1_ALGONAME   = "sha1:\x00"
	SHA256_ALGONAME = "sha256:\x00"
	SUFFIX_EMPTY    = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

type HostManifestPcrs struct {
	Index   PcrIndex     `json:"index"`
	Value   string       `json:"value"`
	PcrBank SHAAlgorithm `json:"pcr_bank"`
}

type EventLog struct {
	TypeID      string   `json:"type_id"`   //oneof-required
	TypeName    string   `json:"type_name"` //oneof-required
	Tags        []string `json:"tags,omitempty"`
	Measurement string   `json:"measurement"` //required
}

type eventLogKeyAttr struct {
	TypeID      string `json:"type_id"`
	Measurement string `json:"measurement"`
}

type TpmEventLog struct {
	Pcr      Pcr        `json:"pcr"`
	TpmEvent []EventLog `json:"tpm_events"` // KWT:  TpmEvents
}

//PCR - To store PCR index with respective PCR bank.
type Pcr struct {
	// Valid PCR index is from 0 to 23.
	Index int `json:"index"`
	// Valid PCR banks are SHA1, SHA256, SHA384 and SHA512.
	Bank string `json:"bank"`
}
type FlavorPcrs struct {
	Pcr              Pcr            `json:"pcr"`         //required
	Measurement      string         `json:"measurement"` //required
	PCRMatches       bool           `json:"pcr_matches,omitempty"`
	EventlogEqual    *EventLogEqual `json:"eventlog_equals,omitempty"`
	EventlogIncludes []EventLog     `json:"eventlog_includes,omitempty"`
}

type EventLogEqual struct {
	Events      []EventLog `json:"events,omitempty"`
	ExcludeTags []string   `json:"exclude_tags,omitempty"`
}

type PcrEventLogMap struct {
	Sha1EventLogs   []TpmEventLog `json:"SHA1,omitempty"`
	Sha256EventLogs []TpmEventLog `json:"SHA256,omitempty"`
	Sha384EventLogs []TpmEventLog `json:"SHA384,omitempty"`
}
type PcrManifest struct {
	Sha1Pcrs       []HostManifestPcrs `json:"sha1pcrs,omitempty"`
	Sha256Pcrs     []HostManifestPcrs `json:"sha2pcrs,omitempty"`
	Sha384Pcrs     []HostManifestPcrs `json:"sha3pcrs,omitempty"`
	PcrEventLogMap PcrEventLogMap     `json:"pcr_event_log_map"`
}

type ImaLogs struct {
	Pcr           Pcr            `json:"pcr,omitempty"` //required
	Measurements  []Measurements `json:"ima_measurements,omitempty"`
	ImaTemplate   string         `json:"ima_template,omitempty"`
	ExpectedValue string         `json:"expected_value,omitempty"`
}

type Measurements struct {
	File        string `json:"file,omitempty"`
	Measurement string `json:"measurement,omitempty"`
}

type ImaLog struct {
	Pcr             Pcr            `json:"pcr"`
	ImaMeasurements []Measurements `json:"ima_measurements"`
	ImaTemplate     string         `json:"ima_template,omitempty"`
}

type ImaTemplate struct {
}

type ImaNGTemplate struct {
}

type ImaSIGTemplate struct {
}

type Template interface {
	getTemplateHash(fileName string, fileHash []byte) ([]byte, error)
}

type PcrIndex int

func (p FlavorPcrs) EqualsWithoutValue(flavorPcr FlavorPcrs) bool {
	return reflect.DeepEqual(p.Pcr.Index, flavorPcr.Pcr.Index) && reflect.DeepEqual(p.Pcr.Bank, flavorPcr.Pcr.Bank)
}

// String returns the string representation of the PcrIndex
func (p PcrIndex) String() string {
	return fmt.Sprintf("pcr_%d", p)
}

const (
	PCR0 PcrIndex = iota
	PCR1
	PCR2
	PCR3
	PCR4
	PCR5
	PCR6
	PCR7
	PCR8
	PCR9
	PCR10
	PCR11
	PCR12
	PCR13
	PCR14
	PCR15
	PCR16
	PCR17
	PCR18
	PCR19
	PCR20
	PCR21
	PCR22
	PCR23
	INVALID_INDEX = -1
)

// Convert the integer value of PcrIndex into "pcr_N" string (for json serialization)
func (pcrIndex PcrIndex) MarshalJSON() ([]byte, error) {
	jsonValue := fmt.Sprintf("pcr_%d", int(pcrIndex))
	return json.Marshal(jsonValue)
}

// Convert the json string value "pcr_N" to PcrIndex
func (pcrIndex *PcrIndex) UnmarshalJSON(b []byte) error {
	var jsonValue string
	if err := json.Unmarshal(b, &jsonValue); err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	index, err := GetPcrIndexFromString(jsonValue)
	if err != nil {
		return errors.Wrap(err, "Could not unmarshal PcrIndex from JSON")
	}

	*pcrIndex = index
	return nil
}

type SHAAlgorithm string

const (
	SHA1    SHAAlgorithm = "SHA1"
	SHA256  SHAAlgorithm = "SHA256"
	SHA384  SHAAlgorithm = "SHA384"
	SHA512  SHAAlgorithm = "SHA512"
	UNKNOWN SHAAlgorithm = "unknown"
)

func GetSHAAlgorithm(algorithm string) (SHAAlgorithm, error) {
	switch algorithm {
	case string(SHA1):
		return SHA1, nil
	case string(SHA256):
		return SHA256, nil
	case string(SHA384):
		return SHA384, nil
	case string(SHA512):
		return SHA512, nil
	}

	return UNKNOWN, errors.Errorf("Could not retrieve SHA from value '%s'", algorithm)
}

// Parses a string value in either integer form (i.e. "8") or "pcr_N"
// where 'N' is the integer value between 0 and 23.  Ex. "pcr_7".  Returns
// an error if the string is not in the correct format or if the index
// value is not between 0 and 23.
func GetPcrIndexFromString(stringValue string) (PcrIndex, error) {
	intString := stringValue

	if strings.Contains(intString, PCR_INDEX_PREFIX) {
		intString = strings.ReplaceAll(stringValue, PCR_INDEX_PREFIX, "")
	}

	intValue, err := strconv.ParseInt(intString, 0, 64)
	if err != nil {
		return INVALID_INDEX, errors.Wrapf(err, "Could not unmarshal PcrIndex from string value '%s'", stringValue)
	}

	if intValue < int64(PCR0) || intValue > int64(PCR23) {
		return INVALID_INDEX, errors.Errorf("Invalid PCR index %d", intValue)
	}

	return PcrIndex(intValue), nil
}

// Finds the Pcr in a PcrManifest provided the pcrBank and index.  Returns
// null if not found.  Returns an error if the pcrBank is not supported
// by intel-secl (currently supports SHA1, SHA256 and SHA384).
func (pcrManifest *PcrManifest) GetPcrValue(pcrBank SHAAlgorithm, pcrIndex PcrIndex) (*HostManifestPcrs, error) {
	// TODO: Is this the right data model for the PcrManifest?  Two things...
	// - Flavor API returns a map[bank]map[pcrindex]
	// - Finding the PCR by bank/index is a linear search.
	var pcrValue *HostManifestPcrs

	switch pcrBank {
	case SHA1:
		for _, pcr := range pcrManifest.Sha1Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	case SHA256:
		for _, pcr := range pcrManifest.Sha256Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	case SHA384:
		for _, pcr := range pcrManifest.Sha384Pcrs {
			if pcr.Index == pcrIndex {
				pcrValue = &pcr
				break
			}
		}
	default:
		return nil, errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return pcrValue, nil
}

// IsEmpty returns true if both the Sha1Pcrs, Sha256Pcrs and Sha384Pcrs
// are empty.
func (pcrManifest *PcrManifest) IsEmpty() bool {
	return len(pcrManifest.Sha1Pcrs) == 0 && len(pcrManifest.Sha256Pcrs) == 0 && len(pcrManifest.Sha384Pcrs) == 0
}

// Finds the EventLogEntry in a PcrEventLogMap provided the pcrBank and index.  Returns
// null if not found.  Returns an error if the pcrBank is not supported
// by intel-secl (currently supports SHA1, SHA256 and SHA384).
func (pcrEventLogMap *PcrEventLogMap) GetEventLogNew(pcrBank string, pcrIndex int) ([]EventLog, int, string, error) {
	var eventLog []EventLog
	var pIndex int
	var bank string

	switch SHAAlgorithm(pcrBank) {
	case SHA1:
		for _, entry := range pcrEventLogMap.Sha1EventLogs {
			if entry.Pcr.Index == pcrIndex {
				eventLog = entry.TpmEvent
				pIndex = entry.Pcr.Index
				bank = entry.Pcr.Bank
				break
			}
		}
	case SHA256:
		for _, entry := range pcrEventLogMap.Sha256EventLogs {
			if entry.Pcr.Index == pcrIndex {
				eventLog = entry.TpmEvent
				pIndex = entry.Pcr.Index
				bank = entry.Pcr.Bank
				break
			}
		}
	case SHA384:
		for _, entry := range pcrEventLogMap.Sha384EventLogs {
			if entry.Pcr.Index == pcrIndex {
				eventLog = entry.TpmEvent
				pIndex = entry.Pcr.Index
				bank = entry.Pcr.Bank
				break
			}
		}
	default:
		return nil, 0, "", errors.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return eventLog, pIndex, bank, nil
}

// Provided an EventLogEntry that contains an array of EventLogs, this function
// will return a new EventLogEntry that contains the events that existed in
// the original ('eventLogEntry') but not in 'eventsToSubtract'.  Returns an error
// if the bank/index of 'eventLogEntry' and 'eventsToSubtract' do not match.
// Note: 'eventLogEntry' and 'eventsToSubract' are not altered.
func (eventLogEntry *TpmEventLog) Subtract(eventsToSubtract *TpmEventLog) (*TpmEventLog, *TpmEventLog, error) {
	if eventLogEntry.Pcr.Bank != eventsToSubtract.Pcr.Bank {
		return nil, nil, errors.Errorf("The PCR banks do not match: '%s' != '%s'", eventLogEntry.Pcr.Bank, eventsToSubtract.Pcr.Bank)
	}

	if eventLogEntry.Pcr.Index != eventsToSubtract.Pcr.Index {
		return nil, nil, errors.Errorf("The PCR indexes do not match: '%d' != '%d'", eventLogEntry.Pcr.Index, eventsToSubtract.Pcr.Index)
	}

	// build a new EventLogEntry that will be populated by the event log entries
	// in the source less those 'eventsToSubtract'.
	subtractedEvents := TpmEventLog{
		Pcr: Pcr{
			Bank:  eventLogEntry.Pcr.Bank,
			Index: eventLogEntry.Pcr.Index,
		},
	}

	mismatchedEvents := TpmEventLog{
		Pcr: Pcr{
			Bank:  eventLogEntry.Pcr.Bank,
			Index: eventLogEntry.Pcr.Index,
		},
	}

	eventsToSubtractMap := make(map[eventLogKeyAttr]EventLog)
	for _, eventLog := range eventsToSubtract.TpmEvent {
		compareInfo := eventLogKeyAttr{
			Measurement: eventLog.Measurement,
			TypeID:      eventLog.TypeID,
		}

		eventLogData := EventLog{
			Tags:     eventLog.Tags,
			TypeName: eventLog.TypeName,
		}
		eventsToSubtractMap[compareInfo] = eventLogData
	}

	//Compare event log entries value (measurement and TypeID) .If mismatched,raise faults
	//else proceed to compare type_name and tags.
	//If these fields are mismatched,then add the mismatch entry details to report(not a fault)
	misMatch := false
	for _, eventLog := range eventLogEntry.TpmEvent {
		compareInfo := eventLogKeyAttr{
			Measurement: eventLog.Measurement,
			TypeID:      eventLog.TypeID,
		}
		if events, ok := eventsToSubtractMap[compareInfo]; ok {

			if len(events.TypeName) != 0 && len(eventLog.TypeName) != 0 {
				if events.TypeName != eventLog.TypeName {
					misMatch = true

				}
			}
			if events.Tags != nil && len(events.Tags) != 0 && len(eventLog.Tags) != 0 {
				if !reflect.DeepEqual(events.Tags, eventLog.Tags) {
					misMatch = true
				}
			}

			if misMatch {
				mismatchedEvents.TpmEvent = append(mismatchedEvents.TpmEvent, eventLog)
				misMatch = false
			}
		} else {
			subtractedEvents.TpmEvent = append(subtractedEvents.TpmEvent, eventLog)
		}
	}

	return &subtractedEvents, &mismatchedEvents, nil
}

// Returns the string value of the "cumulative" hash of the
// an event log.
func (eventLogEntry *TpmEventLog) Replay() (string, error) {
	//get the cumulative hash based on the pcr bank
	cumulativeHash, err := getCumulativeHash(SHAAlgorithm(eventLogEntry.Pcr.Bank))
	if err != nil {
		return "", err
	}

	// use the first EV_NO_ACTION/"StartupLocality" event to send the cumualtive hash
	if eventLogEntry.Pcr.Index == 0 && eventLogEntry.TpmEvent[0].TypeName == StartupLocalityEvent &&
		eventLogEntry.TpmEvent[0].Tags[0] == StartupLocalityTag {
		cumulativeHash[len(cumulativeHash)-1] = 0x3
	}

	for i, eventLog := range eventLogEntry.TpmEvent {
		//if the event is EV_NO_ACTION, skip from summing the hash
		if eventLog.TypeName == StartupLocalityEvent {
			continue
		}
		//get the respective hash based on the pcr bank
		hash := getHash(SHAAlgorithm(eventLogEntry.Pcr.Bank))

		eventHash, err := hex.DecodeString(eventLog.Measurement)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to decode event log %d using hex string '%s'", i, eventLog.Measurement)
		}

		hash.Write(cumulativeHash)
		hash.Write(eventHash)
		cumulativeHash = hash.Sum(nil)
	}

	cumulativeHashString := hex.EncodeToString(cumulativeHash)
	return cumulativeHashString, nil
}

// Returns the string value of the "cumulative" hash of the ima log.
func (imaLog *ImaLogs) Replay() (string, error) {

	cumulativeHash := make([]byte, sha256.Size)

	var template Template
	//we will use input template string instead of constant(IMA_NG_TEMPLATE)
	switch imaLog.ImaTemplate {
	case IMA_NG_TEMPLATE:
		template = new(ImaNGTemplate)
	case "":
		return "", errors.Errorf("Empty Ima Template")
	default:
		return "", errors.Errorf("'%s' template is not supported", imaLog.ImaTemplate)
	}

	for i, fileMeasurements := range imaLog.Measurements {
		hash := sha256.New()
		fileHash, err := hex.DecodeString(fileMeasurements.Measurement)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to decode event log %d using hex string '%s'", i, fileMeasurements.Measurement)
		}

		templateHash, err := template.getTemplateHash(fileMeasurements.File, fileHash)
		if err != nil {
			return "", errors.Wrapf(err, "Failed to calculate template hash %d from file hash '%s'", i, fileMeasurements.Measurement)
		}

		hash.Write(cumulativeHash)
		hash.Write(templateHash)
		cumulativeHash = hash.Sum(nil)
	}

	cumulativeHashString := hex.EncodeToString(cumulativeHash)
	return cumulativeHashString, nil
}

// GetEventLogCriteria returns the EventLogs for a specific PcrBank/PcrIndex, as per latest hostmanifest
func (pcrManifest *PcrManifest) GetEventLogCriteria(pcrBank SHAAlgorithm, pcrIndex PcrIndex) ([]EventLog, error) {
	pI := int(pcrIndex)

	switch pcrBank {
	case "SHA1":
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha1EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	case "SHA256":
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha256EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	case "SHA384":
		for _, eventLogEntry := range pcrManifest.PcrEventLogMap.Sha384EventLogs {
			if eventLogEntry.Pcr.Index == pI {
				return eventLogEntry.TpmEvent, nil
			}
		}
	default:
		return nil, fmt.Errorf("Unsupported sha algorithm %s", pcrBank)
	}

	return nil, fmt.Errorf("Invalid PcrIndex %d", pcrIndex)
}

// GetPcrBanks returns the list of banks currently supported by the PcrManifest
func (pcrManifest *PcrManifest) GetPcrBanks() []SHAAlgorithm {
	var bankList []SHAAlgorithm
	// check if each known digest algorithm is present and return
	if len(pcrManifest.Sha1Pcrs) > 0 {
		bankList = append(bankList, SHA1)
	}
	// check if each known digest algorithm is present and return
	if len(pcrManifest.Sha256Pcrs) > 0 {
		bankList = append(bankList, SHA256)
	}
	// check if each known digest algorithm is present and return
	if len(pcrManifest.Sha384Pcrs) > 0 {
		bankList = append(bankList, SHA384)
	}

	return bankList
}

type c interface {
	GetPcrBanks() []SHAAlgorithm
}

//getHash method returns the hash based on the pcr bank
func getHash(pcrBank SHAAlgorithm) hash.Hash {
	var hash hash.Hash

	switch pcrBank {
	case SHA1:
		hash = sha1.New()
	case SHA256:
		hash = sha256.New()
	case SHA384:
		hash = sha512.New384()
	case SHA512:
		hash = sha512.New()
	}

	return hash
}

//getCumulativeHash method returns the cumulative hash based on the pcr bank
func getCumulativeHash(pcrBank SHAAlgorithm) ([]byte, error) {
	var cumulativeHash []byte

	switch pcrBank {
	case SHA1:
		cumulativeHash = make([]byte, sha1.Size)
	case SHA256:
		cumulativeHash = make([]byte, sha256.Size)
	case SHA384:
		cumulativeHash = make([]byte, sha512.Size384)
	case SHA512:
		cumulativeHash = make([]byte, sha512.Size)
	default:
		return nil, errors.Errorf("Invalid sha algorithm '%s'", pcrBank)
	}

	return cumulativeHash, nil
}

//getTemplateHash method returns the hash based on the pcr bank
func (imaNGTemplate *ImaNGTemplate) getTemplateHash(fileName string, fileHash []byte) ([]byte, error) {
	var paddedHash []byte
	var templateHash []byte

	paddedHash = make([]byte, sha256.Size)
	paddedHash1 := make([]byte, sha1.Size)
	if bytes.Compare(fileHash, paddedHash) == 0 || bytes.Compare(fileHash, paddedHash1) == 0 {
		copy(paddedHash, SUFFIX_SHA256)
		return paddedHash, nil
	}
	templateHash = sha256Templatehash(SHA256_ALGONAME, fileName, fileHash)

	return templateHash, nil
}

//getEndian true = big endian, false = little endian
func getEndian() (ret bool) {
	var i int = 0x1
	bs := (*[unsafe.Sizeof(i)]byte)(unsafe.Pointer(&i))
	if bs[0] == 0 {
		return true
	} else {
		return false
	}
}

//calculate sha256 template hash for sha256 file hash
func sha256Templatehash(algoName string, fileName string, fileHash []byte) []byte {

	const suffix = "\x00"
	fileName0 := append([]byte(fileName), suffix...)
	fileHashAlgoLen := uint32(len(fileHash) + len(algoName))
	fileHashAlgoLenStr := make([]byte, 4)
	fileNameLen := uint32(len(fileName0))
	fileNameLenStr := make([]byte, 4)
	bigEndian := getEndian()
	if bigEndian {
		binary.BigEndian.PutUint32(fileHashAlgoLenStr, fileHashAlgoLen)
		binary.BigEndian.PutUint32(fileNameLenStr, fileNameLen)
	} else {
		binary.LittleEndian.PutUint32(fileHashAlgoLenStr, fileHashAlgoLen)
		binary.LittleEndian.PutUint32(fileNameLenStr, fileNameLen)
	}

	h := sha1.New()
	ss := append(fileHashAlgoLenStr, algoName...)
	ss = append(ss, fileHash...)
	ss = append(ss, fileNameLenStr...)
	ss = append(ss, fileName0...)
	h.Write([]byte(ss))
	sum := h.Sum(nil)

	sum = append(sum, SUFFIX_EMPTY...)
	return sum
}

func (expectedImaLogs *Ima) Subtract(imaLogsToSubtract *Ima) (*Ima, *Ima, error) {
	matched := false
	imaLogsToSubtractMap := make(map[string][]string)

	subtractedImaLogs := Ima{
		ImaTemplate: expectedImaLogs.ImaTemplate,
	}

	mismatchedImaLogs := Ima{
		ImaTemplate: expectedImaLogs.ImaTemplate,
	}

	//Add IMA log file name and its all posible measurements to the map
	for _, imaLogMeasurement := range imaLogsToSubtract.Measurements {
		value, ok := imaLogsToSubtractMap[imaLogMeasurement.File]
		if ok {
			val := append(value, imaLogMeasurement.Measurement)
			imaLogsToSubtractMap[imaLogMeasurement.File] = val
		} else {
			imaLogsToSubtractMap[imaLogMeasurement.File] = []string{imaLogMeasurement.Measurement}
		}
	}

	if len(expectedImaLogs.Measurements) == len(imaLogsToSubtract.Measurements) {
		for _, imaLog := range expectedImaLogs.Measurements {
			if imaLogMeasurement, ok := imaLogsToSubtractMap[imaLog.File]; ok {
				for _, value := range imaLogMeasurement {
					matched = false
					if value == imaLog.Measurement {
						matched = true
						break
					}
				}
				if !matched {
					mismatchedImaLogs.Measurements = append(mismatchedImaLogs.Measurements, imaLog)
				}
			} else {
				subtractedImaLogs.Measurements = append(subtractedImaLogs.Measurements, imaLog)
			}
		}
	}

	lenToCatchUnexpectedEntries := len(imaLogsToSubtract.Measurements)
	if len(expectedImaLogs.Measurements) > len(imaLogsToSubtract.Measurements) {
		for _, imaLog := range expectedImaLogs.Measurements {
			lenToCatchUnexpectedEntries--
			imaLogMeasurement, ok := imaLogsToSubtractMap[imaLog.File]
			if ok && lenToCatchUnexpectedEntries >= 0 {
				for _, value := range imaLogMeasurement {
					matched = false
					if value == imaLog.Measurement {
						matched = true
						break
					}
				}
				if !matched {
					mismatchedImaLogs.Measurements = append(mismatchedImaLogs.Measurements, imaLog)
				}
			} else {
				subtractedImaLogs.Measurements = append(subtractedImaLogs.Measurements, imaLog)
			}
		}
	}

	return &subtractedImaLogs, &mismatchedImaLogs, nil
}
