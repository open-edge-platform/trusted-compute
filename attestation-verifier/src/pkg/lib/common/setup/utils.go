/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"bufio"
	"fmt"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/pkg/errors"
)

// ReadAnswerFileToEnv dumps all the settings from input answer file
// into a environment variables
func ReadAnswerFileToEnv(filename string) error {
	fin, err := os.Open(filename)
	if err != nil {
		return errors.Wrap(err, "Failed to load answer file")
	}
	scanner := bufio.NewScanner(fin)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" ||
			strings.HasPrefix(line, "#") {
			continue
		}
		equalSign := strings.Index(line, "=")
		if equalSign > 0 {
			key := line[0:equalSign]
			val := line[equalSign+1:]
			if key != "" &&
				val != "" {
				err = os.Setenv(key, val)
				if err != nil {
					return errors.Wrap(err, "Failed to set ENV")
				}
			}
		}
	}
	return nil
}

// GetAllEnv takes in a map that contains environment variable names as keys
// and return a map with all such keys mapped to its value in environment
// Keys that are not found are mapped to empty strings
// Such map should be shared with PrintEnvHelp
func GetAllEnv(keys map[string]string) map[string]string {
	r := make(map[string]string)
	for k := range keys {
		r[k] = os.Getenv(k)
	}
	return r
}

const (
	tabWidth = 8
	indent   = 4
)

var indentStr = strings.Repeat(" ", indent)

// PrintEnvHelp prints environment variable help message to
// given io.Writer. With prompt and fixed indent.
// The ENV vars are sorted in alphabetical order.
// Example:
// <prompt>
//     ENV_VAR_ONE      description of ENV_VAR_ONE
//     ENV_VAR_TWO      description of ENV_VAR_TWO
//     ENV_VAR_THREE    description of ENV_VAR_THREE
func PrintEnvHelp(w io.Writer, prompt, envPrefix string, keysAndHelp map[string]string) {
	if w == nil || keysAndHelp == nil {
		return
	}

	if prompt != "" {
		fmt.Fprintln(w, prompt)
	}

	tabW := new(tabwriter.Writer)
	defer func() {
		derr := tabW.Flush()
		if derr != nil {
			log.WithError(derr).Error("Error flushing tab")
		}
	}()
	tabW.Init(w, tabWidth, tabWidth, 2, '\t', 0)

	keys := make([]string, 0, len(keysAndHelp))
	for k := range keysAndHelp {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		fmt.Fprintln(tabW, indentStr+envPrefix+k+"\t"+keysAndHelp[k])
	}
}

func printToWriter(w io.Writer, cmdName, msg string) {
	if w != nil {
		if cmdName != "" {
			msg = cmdName + ": " + msg
		}
		fmt.Fprintln(w, msg)
	}
}

func PrefixUnderscroll(e string) string {
	if e != "" {
		e = strings.ToUpper(e)
		e = strings.ReplaceAll(e, "-", "_")
		if !strings.HasSuffix(e, "_") {
			e += "_"
		}
	}
	return e
}
