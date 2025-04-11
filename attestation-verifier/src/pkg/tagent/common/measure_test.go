/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package common

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strconv"
	"testing"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
)

var mockedExitStatus = 1
var mockedStdout string = "test-string"

const (
	testTBootXm = "../test/resources/tbootxm/bin/"
	testVarDir  = "../test/resources/var/"
	testLogDir  = "../test/resources/log/"
)

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	es := strconv.Itoa(mockedExitStatus)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1",
		"STDOUT=" + mockedStdout,
		"EXIT_STATUS=" + es}
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	xmlFile, err := os.Open("../test/resources/manifest_wlagent.xml")
	if err != nil {
		fmt.Println(err)
	}

	byteValue, _ := ioutil.ReadAll(xmlFile)
	os.Stdout.Write(byteValue)
	defer xmlFile.Close()
	os.Exit(mockedExitStatus)
}

func invalidExecCommand(command string, args ...string) *exec.Cmd {
	// To test cmd.StdoutPipe()
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command("-test.run=TestHelperProcess", "stdout")
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	cmd.Output()
	cmd.Start()
	return cmd
}

func failedExecCommand(command string, args ...string) *exec.Cmd {
	// To test cmd.Start()
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command("-test.run=TestHelperProcess", "stdout")
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func Test_requestHandlerImpl_GetApplicationMeasurement(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	dirManifest := taModel.DirManifestType{
		Exclude:    "",
		FilterType: "regex",
		Include:    ".*",
		Path:       testVarDir,
	}

	fileManifestType := taModel.FileManifestType{
		Path: testVarDir + ".*",
	}

	symlinkManifestType := taModel.SymlinkManifestType{
		Path: testVarDir,
	}

	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		manifest           *taModel.Manifest
		tBootXmMeasurePath string
		logDirPath         string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *taModel.Measurement
		wantErr bool
	}{
		{
			name: "Unable to open wml file",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
		{
			name: "Unable to stat tboot path",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
		{
			name: "Invalid 'measure' file(symlink)",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
		{
			name: "Invalid exec func",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
		{
			name: "Failed exec func",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
		{
			name: "Invalid measurement xml",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavore_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				tBootXmMeasurePath: testTBootXm + "measure",
				logDirPath:         testLogDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}

			if tt.name == "Invalid measurement xml" {
				os.MkdirAll(testLogDir, os.ModePerm)
				os.MkdirAll(testTBootXm, os.ModePerm)
				os.MkdirAll(testVarDir, os.ModePerm)
				CreateTestFile(testVarDir, "../test/resources/manifest_wlagent.xml", "manifest_7a9ac586-40f9-43b2-976b-26667431efca.xml")
				CreateTestFile(testTBootXm, RootCert, "measure")
			} else if tt.name == "Unable to stat tboot path" {
				os.MkdirAll(testLogDir, os.ModePerm)
			} else if tt.name == "Invalid 'measure' file(symlink)" {
				os.MkdirAll(testLogDir, os.ModePerm)
				os.MkdirAll(testTBootXm, os.ModePerm)
				CreateTestFile(testTBootXm, RootCert, "measure_org")
				os.Symlink(testTBootXm+"measure_org", testTBootXm+"measure")
			} else if tt.name == "Invalid exec func" {
				DeleteCommonDir(testTBootXm)
				os.MkdirAll(testTBootXm, os.ModePerm)
				CreateTestFile(testTBootXm, RootCert, "measure")
			}

			_, err := handler.GetApplicationMeasurement(tt.args.manifest, tt.args.tBootXmMeasurePath, tt.args.logDirPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.GetApplicationMeasurement() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
	DeleteCommonDir(testLogDir)
	DeleteCommonDir(testTBootXm)
	DeleteCommonDir(testVarDir)
}
