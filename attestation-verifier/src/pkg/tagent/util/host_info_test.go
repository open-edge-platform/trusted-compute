/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

const (
	platformInfo        = "../test/resources/platform-info"
	invalidPlatformInfo = "../test/resources/test"
	emptyPlatformInfo   = "../test/resources/empty"
)

func TestReadHostInfo(t *testing.T) {
	err := ioutil.WriteFile(invalidPlatformInfo, []byte("test"), 0600)
	assert.NoError(t, err)

	err = ioutil.WriteFile(emptyPlatformInfo, []byte(""), 0600)
	assert.NoError(t, err)

	defer func() {
		err = os.Remove(invalidPlatformInfo)
		assert.NoError(t, err)

		err = os.Remove(emptyPlatformInfo)
		assert.NoError(t, err)
	}()

	tests := []struct {
		name                 string
		platformInfoFilePath string
		wantErr              bool
	}{
		{
			name:                 "Valid case with valid platform info file",
			platformInfoFilePath: platformInfo,
			wantErr:              false,
		},
		{
			name:                 "Invalid case with empty platform info file path",
			platformInfoFilePath: "",
			wantErr:              true,
		},
		{
			name:                 "Invalid case with empty platform info file",
			platformInfoFilePath: emptyPlatformInfo,
			wantErr:              true,
		},
		{
			name:                 "Invalid case with invalid platform info file",
			platformInfoFilePath: invalidPlatformInfo,
			wantErr:              true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadHostInfo(tt.platformInfoFilePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadHostInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
