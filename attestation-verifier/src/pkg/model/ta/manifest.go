/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

type ManifestType interface{}

// xml request format sent from VS...
// <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
// <Manifest xmlns="lib:wml:manifests:1.0" Label="ISecL_Default_Workload_Flavor_v1.0" Uuid="7a9ac586-40f9-43b2-976b-26667431efca" DigestAlg="SHA384">
// 	   <Dir Exclude="" FilterType="regex" Include=".*" Path="/opt/workload-agent/bin"/>
// 	   <Symlink Path="/opt/workload-agent/bin/wlagent"/>
// 	   <File Path="/opt/workload-agent/bin/.*" SearchType="regex"/>
// </Manifest>
type Manifest struct {
	XMLName   xml.Name              `xml:"Manifest"`
	Xmlns     string                `xml:"xmlns,attr"`
	Label     string                `xml:"Label,attr"`
	Uuid      string                `xml:"Uuid,attr"`
	DigestAlg string                `xml:"DigestAlg,attr"`
	Dir       []DirManifestType     `xml:"Dir"`
	File      []FileManifestType    `xml:"File"`
	Symlink   []SymlinkManifestType `xml:"Symlink"`
}

type DirManifestType struct {
	Exclude    string `xml:"Exclude,attr,omitempty"`
	FilterType string `xml:"FilterType,attr,omitempty"`
	Include    string `xml:"Include,attr,omitempty"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type FileManifestType struct {
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type SymlinkManifestType struct {
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}
