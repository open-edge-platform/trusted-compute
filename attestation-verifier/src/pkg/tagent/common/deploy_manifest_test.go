/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/xml"
	"os"
	"testing"

	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
)

const (
	installationDir = "../test/resources/opt/trustagent/"
)

func Test_requestHandlerImpl_DeploySoftwareManifest(t *testing.T) {
	var tagValue = config.TpmConfig{TagSecretKey: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"}
	DeleteCommonDir(installationDir)

	os.MkdirAll(installationDir, os.ModePerm)
	os.MkdirAll(testVarDir, os.ModePerm)

	dirManifest := taModel.DirManifestType{
		Exclude:    "",
		FilterType: "regex",
		Include:    ".*",
		Path:       testVarDir,
	}

	fileManifestType := taModel.FileManifestType{
		Path: testVarDir + "/.*",
	}

	symlinkManifestType := taModel.SymlinkManifestType{
		Path: testVarDir,
	}

	type fields struct {
		cfg *config.TrustAgentConfiguration
	}
	type args struct {
		manifest *taModel.Manifest
		varDir   string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Invalid manifest data location",
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
				varDir: "pre/test/path" + testVarDir,
			},
			wantErr: true,
		},
		{
			name: "DeploySoftwareManifest by reading manifest data",
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
				varDir: testVarDir,
			},
			wantErr: false,
		},
		{
			name: "Invalid label name in manifest data",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "ISecL_Default_Workload_Flavor_v1.0",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				varDir: testVarDir,
			},
			wantErr: true,
		},
		{
			name: "Empty label in manifest data",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				varDir: testVarDir,
			},
			wantErr: true,
		},
		{
			name: "Invalid UUID of manifest data",
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
					Uuid:      "7a9ac5840f943b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				varDir: testVarDir,
			},
			wantErr: true,
		},
		{
			name: "Invalid label string of manifest data",
			fields: fields{
				cfg: &config.TrustAgentConfiguration{
					Tpm: tagValue,
				},
			},
			args: args{
				manifest: &taModel.Manifest{
					XMLName:   xml.Name{Local: "Person"},
					Xmlns:     "lib:wml:manifests:1.0",
					Label:     "7777u+x0000\u0000088899",
					Uuid:      "7a9ac586-40f9-43b2-976b-26667431efca",
					DigestAlg: "SHA384",
					Dir:       []taModel.DirManifestType{dirManifest},
					File:      []taModel.FileManifestType{fileManifestType},
					Symlink:   []taModel.SymlinkManifestType{symlinkManifestType},
				},
				varDir: testVarDir,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.name == "DeploySoftwareManifest by reading manifest data" {
				os.MkdirAll(constants.VarDir, os.ModePerm)
			}

			handler := &requestHandlerImpl{
				cfg: tt.fields.cfg,
			}
			if err := handler.DeploySoftwareManifest(tt.args.manifest, tt.args.varDir); (err != nil) != tt.wantErr {
				t.Errorf("requestHandlerImpl.DeploySoftwareManifest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	DeleteCommonDir(installationDir)
}
