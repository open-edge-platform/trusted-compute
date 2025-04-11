/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package exec

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ExecuteCommand is used to execute a linux command line command and return the output of the command with an error if it exists.
func ExecuteCommand(cmd string, args []string) (string, error) {
	out, err := exec.Command(cmd, args...).Output()
	return string(out), err
}

// RunCommandWithTimeout takes a command line and returs the stdout and stderr output
// If command does not terminate within 'timeout', it returns an error
//Todo : vcheeram : Move this to a common library. Keeping as exported for now
func RunCommandWithTimeout(commandLine string, timeout int) (stdout, stderr string, err error) {

	// Create a new context and add a timeout to it
	// log.Println(commandLine)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel() // The cancel should be deferred so resources are cleaned up

	r := csv.NewReader(strings.NewReader(commandLine))
	r.Comma = ' '
	records, err := r.Read()
	if records == nil {
		return "", "", fmt.Errorf("No command to execute - commandLine - %s", commandLine)
	}

	var cmd *exec.Cmd
	if len(records) > 1 {
		cmd = exec.CommandContext(ctx, records[0], records[1:]...)
	} else {
		cmd = exec.CommandContext(ctx, records[0])
	}

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	err = cmd.Run()
	stdout = outb.String()
	stderr = errb.String()

	return stdout, stderr, err

}

// MakeFilePathFromEnvVariable creates a filepath given an environment variable and the filename
// createDir will create a directory if one does not exist
func MkDirFilePathFromEnvVariable(dirEnvVar, filename string, createDir bool) (string, error) {

	if filename == "" {
		return "", fmt.Errorf("Filename is empty")
	}
	dir := os.Getenv(dirEnvVar)
	if dir == "" {
		return "", fmt.Errorf("Environment variable %s not set", dirEnvVar)
	}
	dir = strings.TrimSpace(dir)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if createDir {
			mkDirErr := os.Mkdir(dir, 0600)
			if mkDirErr != nil {
				return "", fmt.Errorf("Error while creating the directory %s", dir)
			}
		} else {
			return "", fmt.Errorf("Directory %s does not exist", dir)
		}
	}
	return filepath.Join(dir, filename), nil
}

// GetValueFromEnvBody return the value of a key from a config/environment
// file content. We are passing the contents of a file here and not the filename
// The type of file is a env file where the format is line seperated 'key=value'
//
// TODO: Unit test this with extra whitespace
func GetValueFromEnvBody(content, keyName string) (value string, err error) {
	if strings.TrimSpace(content) == "" || strings.TrimSpace(keyName) == "" {
		return "", errors.New("content and keyName cannot be empty")
	}
	//the config file should have the keyname as part of the beginning of line
	r, err := regexp.Compile(`(?im)^` + keyName + `\s*=\s*(.*)`)
	if err != nil {
		return
	}
	rs := r.FindStringSubmatch(content)
	if rs != nil {
		return rs[1], nil
	}
	return "", fmt.Errorf("Could not find Value for %s", keyName)
}
