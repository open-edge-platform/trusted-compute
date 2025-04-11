/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"os"
	"testing"
)

func TestSetupAnswerFile(t *testing.T) {
	testFilename := "../test/answer-test.txt"
	ans := map[string]string{
		"TEST_ENV_ONE":   "1",
		"TEST_ENV_TWO":   "12",
		"TEST_ENV_THREE": "123",
		"TEST_ENV_FOUR":  "1234",
		"TEST_ENV_FIVE":  "12345",
	}
	err := ReadAnswerFileToEnv(testFilename)
	if err != nil {
		t.Error("Failed to load answer file", err.Error())
	}
	// check if answer is in environment variables
	for k, v := range ans {
		valRead := os.Getenv(k)
		if valRead == "" {
			t.Error("Can not find map key:", k)
		}
		if valRead != v {
			t.Error("Incorrect key value:", k, valRead)
		}
	}
}

const testPrompt = "test prompt"

var testHelpMsg = map[string]string{
	"TEST_ENV_ONE":   "111",
	"TEST_ENV_TWO":   "121212",
	"TEST_ENV_THREE": "123123123",
}

func setTestEnv() {
	for k, v := range testHelpMsg {
		os.Setenv(k, v)
	}
}

// Sample output:
// test prompt
//     TEST_ENV_THREE      123123123
//     TEST_ENV_ONE        111
//     TEST_ENV_TWO        121212
// test prompt
//     TEST_PREFIX_TEST_ENV_THREE  123123123
//     TEST_PREFIX_TEST_ENV_ONE    111
//     TEST_PREFIX_TEST_ENV_TWO    121212
// test prompt
//     TEST_PREFIXTEST_ENV_ONE     111
//     TEST_PREFIXTEST_ENV_TWO     121212
//     TEST_PREFIXTEST_ENV_THREE   123123123
func TestPrintEnvHelp(t *testing.T) {
	PrintEnvHelp(os.Stdout, testPrompt, "", testHelpMsg)
	PrintEnvHelp(os.Stdout, testPrompt, "TEST_PREFIX_", testHelpMsg)
	PrintEnvHelp(os.Stdout, testPrompt, "TEST_PREFIX", testHelpMsg)
}

func TestGetAllEnv(t *testing.T) {
	setTestEnv()
	allTestEnv := GetAllEnv(testHelpMsg)
	for k, v := range testHelpMsg {
		valFromEnv, ok := allTestEnv[k]
		if !ok {
			t.Error("Can not find env key:", k)
		}
		if valFromEnv != v {
			t.Error("Incorrect key value:", k, valFromEnv)
		}
	}
}
