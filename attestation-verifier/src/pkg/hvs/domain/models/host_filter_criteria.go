/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package models

import (
	"errors"
	"github.com/google/uuid"
)

type HostFilterCriteria struct {
	Id             uuid.UUID
	HostHardwareId uuid.UUID
	NameEqualTo    string
	NameContains   string
	Key            string
	Value          string
	IdList         []uuid.UUID
	Trusted        *bool
	OrderBy        OrderType
	Limit          int
	AfterId        int
}

type OrderType string

const (
	Ascending  OrderType = "asc"
	Descending           = "desc"
)

func (ot OrderType) String() string {
	orderTypes := [...]string{"asc", "desc"}

	x := string(ot)
	for _, v := range orderTypes {
		if v == x {
			return x
		}
	}

	return "asc"
}

func GetOrderType(oType string) (OrderType, error) {
	switch oType {
	case "asc":
		return Ascending, nil
	case "desc":
		return Descending, nil
	default:
		return "", errors.New("Invalid order type")
	}
}
