/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package serialize

import (
	"fmt"
	"testing"
)

type ObjGroup1 struct {
	GroupField1 string
	GroupField2 int
	GroupField3 bool
}
type ObjGroup2 struct {
	GroupField1 string
	GroupField2 int64
	GroupField3 bool
}
type ObjGroup3 struct {
	GroupField1 string
	GroupField2 uint16
	GroupField3 bool
}

type TestObj struct {
	G1 ObjGroup1
	G2 ObjGroup2
	G3 ObjGroup3

	ObjField1 string
	ObjField2 float64
	ObjField3 bool
}

func fillObjContent(t *TestObj) {
	t.G1.GroupField1 = "123"
	t.G2.GroupField2 = 123
	t.G3.GroupField3 = true

	t.G2.GroupField1 = "123"
	t.G2.GroupField2 = 3123123123132
	t.G2.GroupField3 = false

	t.G3.GroupField1 = "123"
	t.G3.GroupField2 = 65535
	t.G3.GroupField3 = true

	t.ObjField1 = "123"
	t.ObjField2 = 123.456
	t.ObjField3 = false
}

// Run with command: go test --count=1 -v ./...
// Look at standard output and created file to verify implementation
func TestSave(t *testing.T) {
	test := TestObj{}
	fillObjContent(&test)
	SaveToJsonFile("test.json", &test)
	SaveToYamlFile("test.yml", &test)
}

func TestLoad(t *testing.T) {

	j := TestObj{}
	y := TestObj{}

	LoadFromJsonFile("test.json", &j)
	LoadFromJsonFile("test.json", &y)

	fmt.Println(j)
	fmt.Println(y)
}
