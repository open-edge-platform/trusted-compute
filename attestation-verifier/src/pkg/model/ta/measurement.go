/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

// Measurement represents the details of an individual integrity measurement taken on a target Host
type DirectoryMeasurementType struct {
	Value      string `xml:",chardata"`
	Include    string `xml:"Include,attr,omitempty"`
	Exclude    string `xml:"Exclude,attr,omitempty"`
	FilterType string `xml:"FilterType,attr,omitempty"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type FileMeasurementType struct {
	Value      string `xml:",chardata"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type SymlinkMeasurementType struct {
	Value      string `xml:",chardata"`
	Path       string `xml:"Path,attr"`
	SearchType string `xml:"SearchType,attr,omitempty"`
}

type Measurement struct {
	XMLName        xml.Name                   `xml:"Measurement"`
	File           []FileMeasurementType      `xml:"File"`
	Dir            []DirectoryMeasurementType `xml:"Dir"`
	Symlink        []SymlinkMeasurementType   `xml:"Symlink"`
	CumulativeHash string                     `xml:"CumulativeHash"`
	DigestAlg      string                     `xml:"DigestAlg,attr,omitempty"`
	Label          string                     `xml:"Label,attr,omitempty"`
	Uuid           string                     `xml:"Uuid,attr,omitempty"`
}

type MeasurementType string

const (
	MeasurementTypeFile    MeasurementType = "fileMeasurementType"
	MeasurementTypeDir     MeasurementType = "directoryMeasurementType"
	MeasurementTypeSymlink MeasurementType = "symlinkMeasurementType"
)

type FlavorMeasurement struct {
	Type       MeasurementType `json:"type"`
	Value      string          `json:"value"`
	Path       string          `json:"Path"`
	Include    string          `json:"Include,omitempty"`
	Exclude    string          `json:"Exclude,omitempty"`
	SearchType string          `json:"SearchType,omitempty"`
	FilterType string          `json:"FilterType,omitempty"`
}

func (flavorMeasurement *FlavorMeasurement) FromFile(file FileMeasurementType) {

	*flavorMeasurement = FlavorMeasurement{
		Type:       MeasurementTypeFile,
		Value:      file.Value,
		Path:       file.Path,
		SearchType: file.SearchType,
	}
}

func (flavorMeasurement *FlavorMeasurement) FromDir(dir DirectoryMeasurementType) {

	*flavorMeasurement = FlavorMeasurement{
		Type:       MeasurementTypeDir,
		Value:      dir.Value,
		Path:       dir.Path,
		SearchType: dir.SearchType,
		Include:    dir.Include,
		Exclude:    dir.Exclude,
		FilterType: dir.FilterType,
	}
}

func (flavorMeasurement *FlavorMeasurement) FromSymlink(symlink SymlinkMeasurementType) {

	*flavorMeasurement = FlavorMeasurement{
		Type:       MeasurementTypeSymlink,
		Value:      symlink.Value,
		Path:       symlink.Path,
		SearchType: symlink.SearchType,
	}
}
