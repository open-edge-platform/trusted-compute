/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package utils

import (
	"net/url"
	"reflect"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

func TestValidateQueryParams(t *testing.T) {
	type args struct {
		params       url.Values
		validQueries map[string]bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid query parameters",
			args: args{
				params:       url.Values{"test": []string{"test"}},
				validQueries: map[string]bool{"test": true},
			},
			wantErr: false,
		},
		{
			name: "Invalid query parameter",
			args: args{
				params:       url.Values{"test": []string{"test"}},
				validQueries: map[string]bool{"test_data": true},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateQueryParams(tt.args.params, tt.args.validQueries); (err != nil) != tt.wantErr {
				t.Errorf("ValidateQueryParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseDateQueryParam(t *testing.T) {
	type args struct {
		dt string
	}
	timeVal, err := time.Parse("2006-01-02", "2022-01-29")
	if err != nil {
		log.Error("Error in parsing time")
	}
	tests := []struct {
		name    string
		args    args
		want    time.Time
		wantErr bool
	}{
		{
			name: "Valid date format",
			args: args{
				dt: "2022-01-29",
			},
			want:    timeVal,
			wantErr: false,
		},
		{
			name: "Invalid date format",
			args: args{
				dt: "test",
			},
			want:    time.Time{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDateQueryParam(tt.args.dt)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDateQueryParam() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseDateQueryParam() = %v, want %v", got, tt.want)
			}
		})
	}
}
