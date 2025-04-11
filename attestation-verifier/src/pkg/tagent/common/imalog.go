/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"bufio"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"

	hvsModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
)

// ImaSystemDetails used to hold ima algorithm and template tpye of ima_policy
type ImaSystemDetails struct {
	ImaHashAlgorithm string
	ImaTemplate      string
}

// ImaPaths use to store the path of system files used in ima
type ImaPaths struct {
	ProcFilePath  string
	AsciiFilePath string
}

// ImaInfo use to store imalog and other parameter used for ima
type ImaInfo struct {
	ImaLog string
}

// GetImaMeasurements - Function to get all IMA logs
func (imaPath *ImaPaths) getImaMeasurements() (*ImaInfo, error) {
	log.Trace("common/imalog:getImaMeasurements() Entering")
	defer log.Trace("common/imalog:getImaMeasurements() Leaving")

	var imaInfo ImaInfo

	// Check if /proc/cmdline is exist or not
	if _, err := os.Stat(imaPath.ProcFilePath); os.IsNotExist(err) {
		// If the file does not exist, do not include imalog in the quote
		return nil, errors.Errorf("common/imalog:getImaMeasurements() File '%s' containing IMA measure info in system was not present", imaPath.ProcFilePath)
	}

	if _, err := os.Stat(imaPath.AsciiFilePath); os.IsNotExist(err) {
		// If the file does not exist, do not include imalog in the quote
		return nil, errors.Errorf("common/imalog:getImaMeasurements() File '%s' containing IMA log was not present", imaPath.AsciiFilePath)
	}

	imaSystemDetails := ImaSystemDetails{}
	err := imaSystemDetails.collectImaSystemDetails(imaPath.ProcFilePath)
	if err != nil {
		log.WithError(err).Error("common/imalog:getImaMeasurements() There was an error updating IMA variables")
		return nil, err
	}

	// Read all measurement from /sys/kernel/security/ima/ascii_runtime_measurements
	imaInfo.ImaLog, err = imaSystemDetails.getImaLog(imaPath.AsciiFilePath)
	if err != nil {
		log.WithError(err).Error("common/imalog:getImaMeasurements() There was an error getting ima-log")
		return nil, err
	}

	return &imaInfo, nil
}

// CollectImaSystemDetails - Function to check if ima is enabled and collect the sha type
func (imaSystemDetails *ImaSystemDetails) collectImaSystemDetails(procFilePath string) error {
	log.Trace("common/imalog:collectImaSystemDetails() Entering")
	defer log.Trace("common/imalog:collectImaSystemDetails() Leaving")

	// Read the whole file at once
	procFileData, err := ioutil.ReadFile(procFilePath)
	if err != nil {
		return errors.Wrapf(err, "common/imalog:collectImaSystemDetails() There was an error in reading %s", procFilePath)
	}

	strData := string(procFileData)
	// Check strData contains which sha algorithm
	switch {
	case strings.Contains(strData, constants.ImaHashSha256):
		imaSystemDetails.ImaHashAlgorithm = string(constants.SHA256)
	default:
		log.Debugf("common/imalog:collectImaSystemDetails() Invalid ima sha algorithm. Only %s is supported", constants.ImaHashSha256)
		return errors.Errorf("common/imalog:collectImaSystemDetails() Invalid ima sha algorithm. Only %s is supported", constants.ImaHashSha256)
	}

	// Check strData contains which template
	switch {
	case strings.Contains(strData, constants.TemplateNG):
		imaSystemDetails.ImaTemplate = hvsModel.IMA_NG_TEMPLATE
	case strings.Contains(strData, constants.TemplateSIG):
		imaSystemDetails.ImaTemplate = hvsModel.IMA_SIG_TEMPLATE
	case strings.Contains(strData, constants.TemplateIMA):
		imaSystemDetails.ImaTemplate = hvsModel.IMA_TEMPLATE
	default:
		log.Debug("common/imalog:collectImaSystemDetails() Setting default IMA Template as ima-ng")
		imaSystemDetails.ImaTemplate = hvsModel.IMA_NG_TEMPLATE
	}
	return nil
}

func (imaSystemDetails *ImaSystemDetails) getImaLog(asciiFilePath string) (string, error) {
	log.Trace("common/imalog:getImaLog() Entering")
	defer log.Trace("common/imalog:getImaLog() Leaving")

	imaLog, err := imaSystemDetails.readPcr10Events(asciiFilePath)
	if err != nil {
		return "", errors.Wrapf(err, "common/imalog:getImaLog() There was an error in reading ima-log from %s", asciiFilePath)
	}

	imaLog.Pcr.Bank = imaSystemDetails.ImaHashAlgorithm
	imaLog.Pcr.Index = constants.PCR10
	imaLog.ImaTemplate = imaSystemDetails.ImaTemplate
	// Marshal the structure into string
	marshalledImaLog, err := json.Marshal(imaLog)
	if err != nil {
		return "", errors.Wrapf(err, "common/imalog:getImaLog() There was an error in marshalling IMA event log data")
	}
	return string(marshalledImaLog), nil
}

// ReadPcr10Events - Function to read all pcr 10 events from specified input offset
func (imaSystemDetails *ImaSystemDetails) readPcr10Events(asciiFilePath string) (*hvsModel.ImaLog, error) {
	log.Trace("common/imalog:readPcr10Events() Entering")
	defer log.Trace("common/imalog:readPcr10Events() Leaving")

	file, err := os.Open(asciiFilePath)
	if err != nil {
		return nil, errors.Wrapf(err, "common/imalog:readPcr10Events() There was an error opening %s", asciiFilePath)
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Errorf("common/imalog:readPcr10Events() There was an error closing %s", asciiFilePath)
		}
	}()

	// Need to remove this check in future
	if !strings.EqualFold(imaSystemDetails.ImaTemplate, hvsModel.IMA_NG_TEMPLATE) {
		return nil, errors.Errorf("common/imalog:readPcr10Events() Unsupported template %s", imaSystemDetails.ImaTemplate)
	}

	var imaLog hvsModel.ImaLog
	var imaEvents []hvsModel.Measurements
	reader := bufio.NewReader(file)

	for {
		var imaEvent hvsModel.Measurements
		// Read each line of data from ascii_runtime_measurements file
		line, err := read(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, errors.Wrapf(err, "common/imalog:readPcr10Events() There was an error in reading the line from %s", asciiFilePath)
		}

		// Parse line read in array by splitting with spaces
		array := strings.Split(string(line), " ")
		imaEvent.File = array[4]
		//sample data - 10 d764b27478cf00d0eeb2407e5cf6f6dae89716e0 ima-ng sha256:a9ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893 boot_aggregate
		//array[0] - 10 --> pcr index
		//array[1] - d764b27478cf00d0eeb2407e5cf6f6dae89716e0 (Not used) --> template-hash: sha1 hash(filedata-hash length, filedata-hash, pathname length, pathname)
		//array[2] - ima-ng --> ima template
		//array[3] - sha256:a9ea73d04dc53931c8729429295ccc4bd3f613612d6732334982781da6b25893 --> file_hash_algorithm: file hash
		//array[4] - file name

		if strings.EqualFold(array[2], hvsModel.IMA_TEMPLATE) {
			imaEvent.Measurement = array[3]
		} else {
			resMeasurement := strings.Split(array[3], ":")
			if len(resMeasurement) != 2 {
				return nil, errors.Errorf("common/imalog:readPcr10Events() Invalid File Hash in %s", asciiFilePath)
			}
			imaEvent.Measurement = resMeasurement[1]
		}

		imaEvents = append(imaEvents, imaEvent)
	}

	imaLog.ImaMeasurements = append(imaLog.ImaMeasurements, imaEvents...)
	return &imaLog, nil
}

// Read with Readline function
func read(r *bufio.Reader) ([]byte, error) {
	log.Trace("common/imalog:read() Entering")
	defer log.Trace("common/imalog:read() Leaving")

	var (
		isPrefix = true
		err      error
		line, ln []byte
	)

	for isPrefix && err == nil {
		line, isPrefix, err = r.ReadLine()
		ln = append(ln, line...)
	}

	return ln, err
}
