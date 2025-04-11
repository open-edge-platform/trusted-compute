/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"
	"path"

	"gopkg.in/yaml.v3"
)

func readConfig(path string) (map[string]interface{}, error) {

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read config file: %v", err)
	}
	data := make(map[string]interface{}, 0)
	if err := yaml.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("unable to decode config content: %v", err)
	}
	return data, nil
}

func main() {

	templateFile := os.Args[1]
	data, err := readConfig(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}

	configFile, err := os.Create(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		err = configFile.Close()
		if err != nil {
			log.Printf("Error closing config file: %v", err)
		}
	}()

	tmpl := template.New(path.Base(templateFile))
	tmpl, err = tmpl.ParseFiles(templateFile)
	if err != nil {
		log.Fatal("Error Parsing template: ", err)
	}
	err = tmpl.Execute(configFile, data)
	if err != nil {
		log.Fatal("Error executing template: ", err)
	}
}
