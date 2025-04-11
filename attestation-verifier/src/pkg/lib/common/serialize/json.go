/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"encoding/json"
	"io/ioutil"
	"os"

	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	log "github.com/sirupsen/logrus"
)

// SaveToJsonFile saves input object to given file path
func SaveToJsonFile(path string, obj interface{}) error {

	file, err := cos.OpenFileSafe(path, "", os.O_CREATE|os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Error closing file")
		}
	}()
	return json.NewEncoder(file).Encode(obj)
}

// LoadFromJsonFile loads json file on given path to an output object
// example: LoadFromJsonFile(appStatePath, &AppStateStruct{})
func LoadFromJsonFile(path string, out interface{}) error {

	jsonFile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonFile, out)
	if err != nil {
		return err
	}
	return nil
}
