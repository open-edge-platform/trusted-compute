/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package fds

import (
	"errors"
	"github.com/google/uuid"
)

type HostFilterCriteria struct {
	HardwareId   uuid.UUID
	HostName     string
	NameContains string
	OrderBy      OrderType
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
