/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"

	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	"gopkg.in/yaml.v3"
)

// SaveToYamlFile saves input object to given file path
func SaveToYamlFile(path string, obj interface{}) error {

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

	return yaml.NewEncoder(file).Encode(obj)
}

// LoadFromYamlFile loads yaml file on given path to an output object
// example: LoadFromYamlFile(configPath, &ConfigStruct{})
func LoadFromYamlFile(path string, out interface{}) error {

	yamlFile, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, out)
	if err != nil {
		return err
	}
	return nil
}
