/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs

import (
	"errors"

	"github.com/google/uuid"
)

type HostCollection struct {
	Next     string  `json:"next,omitempty" xml:"next"`
	Previous string  `json:"prev,omitempty" xml:"prev"`
	Hosts    []*Host `json:"hosts" xml:"host"`
}

type Host struct {
	// swagger:strfmt uuid
	RowId            int       `json:"-"`
	Id               uuid.UUID `json:"id,omitempty"`
	HostName         string    `json:"host_name"`
	Description      string    `json:"description,omitempty"`
	ConnectionString string    `json:"connection_string"`
	// swagger:strfmt uuid
	HardwareUuid     *uuid.UUID             `json:"hardware_uuid,omitempty"`
	FlavorgroupNames []string               `json:"flavorgroup_names,omitempty"`
	Report           *TrustReport           `json:"report,omitempty"`
	Trusted          *bool                  `json:"trusted,omitempty"`
	ConnectionStatus *HostStatusInformation `json:"status,omitempty"`
}

type HostCreateRequest struct {
	HostName         string   `json:"host_name"`
	Description      string   `json:"description,omitempty"`
	ConnectionString string   `json:"connection_string"`
	FlavorgroupNames []string `json:"flavorgroup_names,omitempty"`
}

type HostFlavorgroupCollection struct {
	HostFlavorgroups []HostFlavorgroup `json:"flavorgroup_host_links" xml:"flavorgroup_host_link"`
}

type HostFlavorgroup struct {
	// swagger:strfmt uuid
	HostId uuid.UUID `json:"host_id,omitempty"`
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}

type HostFlavorgroupCreateRequest struct {
	// swagger:strfmt uuid
	FlavorgroupId uuid.UUID `json:"flavorgroup_id,omitempty"`
}

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
