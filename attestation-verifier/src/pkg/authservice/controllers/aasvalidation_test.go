/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package controllers

import (
	"strings"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/stretchr/testify/assert"
)

func TestValidateRoleString(t *testing.T) {

	err := ValidateRoleString("administrator")
	assert.NoError(t, err)

	err = ValidateRoleString("") // empty, not ok
	assert.Error(t, err)

	err = ValidateRoleString(strings.Repeat("a", 40)) // 40 or less, ok
	assert.NoError(t, err)

	err = ValidateRoleString(strings.Repeat("a", 41)) // more than 40, not ok
	assert.Error(t, err)

	err = ValidateRoleString("administrator-at-large") // dashes ok
	assert.NoError(t, err)

	err = ValidateRoleString("administrator.at.large") // dots ok
	assert.NoError(t, err)

	err = ValidateRoleString("kahuna,big") // comma ok
	assert.NoError(t, err)

	err = ValidateRoleString("big@kahuna.com")
	assert.NoError(t, err)

}

func TestValidateServiceString(t *testing.T) {

	err := ValidateServiceString("AAS")
	assert.NoError(t, err)

	err = ValidateServiceString("") // empty, not ok
	assert.Error(t, err)

	err = ValidateServiceString(strings.Repeat("a", 20)) // 20 or less, ok
	assert.NoError(t, err)

	err = ValidateServiceString(strings.Repeat("a", 21)) // more than 20, not ok
	assert.Error(t, err)

	err = ValidateServiceString("service-name") // dashes ok
	assert.NoError(t, err)

	err = ValidateServiceString("service.name") // dots ok
	assert.NoError(t, err)

	err = ValidateServiceString("name,service") // comma ok
	assert.NoError(t, err)

	err = ValidateServiceString("service@name.com")
	assert.NoError(t, err)
}

func TestValidateContextString(t *testing.T) {

	err := ValidateContextString("") // empty is ok
	assert.NoError(t, err)

	err = ValidateContextString(strings.Repeat("a", 512)) // 512 len is ok
	assert.NoError(t, err)

	err = ValidateContextString(strings.Repeat("a", 513)) // Longer than 512 is not ok
	assert.Error(t, err)

	err = ValidateContextString("cn=John Doe, ou=People, dc=*.intel.com") // ex distinguished name
	assert.NoError(t, err)
}

func TestValidateUserNameString(t *testing.T) {

	err := validation.ValidateUserNameString("") // empty is not ok
	assert.Error(t, err)

	err = validation.ValidateUserNameString(strings.Repeat("a", 255)) // 255 len is ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString(strings.Repeat("a", 256)) // Longer than 255 is not ok
	assert.Error(t, err)

	err = validation.ValidateUserNameString("george")
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george of the jungle") // no spaces
	assert.Error(t, err)

	err = validation.ValidateUserNameString("george-of-the-jungle") // dashes ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george.of.the.jungle") // dots ok
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("george@thejungle.com") // email
	assert.NoError(t, err)

	err = validation.ValidateUserNameString("`~!@#$%^&*()-=_+[]{}\\|;:'\",<.>/?") // no other characters
	assert.Error(t, err)
}

func TestValidatePasswordString(t *testing.T) {

	err := validation.ValidatePasswordString("") // empty is not ok
	assert.Error(t, err)

	err = validation.ValidatePasswordString(strings.Repeat("a", 255)) // 255 len is ok
	assert.NoError(t, err)

	err = validation.ValidatePasswordString(strings.Repeat("a", 256)) // Longer than 255 is not ok
	assert.Error(t, err)

	// no restriction on characters...
	err = validation.ValidatePasswordString("`~!@#$%^&*()_+1234567890-={}[]\\|:;'\",./<>?abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	assert.NoError(t, err)
}

func TestValidatePermissions(t *testing.T) {
	type args struct {
		permissions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate permission with valid length",
			args: args{
				permissions: []string{"ValidPermission"},
			},
			wantErr: false,
		},
		{
			name: "Validate permission with invalid length",
			args: args{
				permissions: []string{"SW50ZWyuIFNlY3VyaXR5IExpYnJhcmllcyBmb3IgRGF0YSBDZW50ZXIgKEludGVsriBTZWNMLURDKSBlbmFibGVzIHNlY3VyaXR5IHVzZSBjYXNlcyBmb3IgZGF0YSBjZW50ZXIgdXNpbmcgSW50ZWyuIGhhcmR3YXJlIHNlY3VyaXR5IHRlY2hub2xvZ2llcy4KCkhhcmR3YXJlLWJhc2VkIGNsb3VkIHNlY3VyaXR5IHNvbHV0aW9ucyBwcm92aWRlIGEgaGlnaGVyIGxldmVsIG9mIHByb3RlY3Rpb24gYXMgY29tcGFyZWQgdG8gc29mdHdhcmUtb25seSBzZWN1cml0eSBtZWFzdXJlcy4gVGhlcmUgYXJlIG1hbnkgSW50ZWwgcGxhdGZvcm0gc2VjdXJpdHkgdGVjaG5vbG9naWVzLCB3aGljaCBjYW4gYmUgdXNlZCB0byBzZWN1cmUgY3VzdG9tZXJzJyBkYXRhLiBDdXN0b21lcnMgaGF2ZSBmb3VuZCBhZG9wdGluZyBhbmQgZGVwbG95aW5nIHRoZXNlIHRlY2hub2xvZ2llcyBhdCBhIGJyb2FkIHNjYWxlIGNoYWxsZW5naW5nLCBkdWUgdG8gdGhlIGxhY2sgb2Ygc29sdXRpb24gaW50ZWdyYXRpb24gYW5kIGRlcGxveW1lbnQgdG9vbHMuIEludGVsriBTZWN1cml0eSBMaWJyYXJpZXMgZm9yIERhdGEgQ2VudGVycyAoSW50ZWyuIFNlY0wgLSBEQykgd2FzIGJ1aWx0IHRvIGFpZCBvdXIgY3VzdG9tZXJzIGluIGFkb3B0aW5nIGFuZCBkZXBsb3lpbmcgSW50ZWwgU2VjdXJpdHkgZmVhdHVyZXMsIHJvb3RlZCBpbiBzaWxpY29uLCBhdCBzY2FsZS4="},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePermissions(tt.args.permissions); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
