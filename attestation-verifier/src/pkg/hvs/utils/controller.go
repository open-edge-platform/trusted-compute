/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/pkg/errors"
	"net/url"
	"time"
)

const MaxQueryParamsLength = 50

func ValidateQueryParams(params url.Values, validQueries map[string]bool) error {
	defaultLog.Trace("utils/controller:ValidateQueryParams() Entering")
	defer defaultLog.Trace("utils/controller:ValidateQueryParams() Leaving")
	if len(params) > MaxQueryParamsLength {
		return errors.New("Invalid query parameters provided. Number of query parameters exceeded maximum value")
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return errors.New("Invalid query parameter provided. Refer to product guide for details.")
		}
	}
	return nil
}

func ParseDateQueryParam(dt string) (time.Time, error) {
	defaultLog.Trace("utils/controller:ParseDateQueryParam() Entering")
	defer defaultLog.Trace("utils/controller:ParseDateQueryParam() Leaving")
	pTime, err := time.Parse(constants.ParamDateFormat, dt)
	if err != nil {
		pTime, err = time.Parse(constants.ParamDateTimeFormat, dt)
		if err != nil {
			pTime, err = time.Parse(time.RFC3339Nano, dt)
			if err != nil {
				return time.Time{}, errors.Wrap(err, "One of Valid date formats (YYYY-MM-DD)|(YYYY-MM-DD hh:mm:ss)|(YYYY-MM-DDThh:mm:ss.000Z)|(YYYY-MM-DDThh:mm:ss.000000Z) must be specified")
			}
		}
	}
	return pTime, nil
}
