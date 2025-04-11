/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package slice

import "reflect"

func Contains(s interface{}, elem interface{}) bool {
	slice := reflect.ValueOf(s)
	if slice.Kind() == reflect.Slice {
		for index := 0; index < slice.Len(); index++ {
			//panics if slice element points to an unexported struct field
			if slice.Index(index).Interface() == elem {
				return true
			}
		}
	}
	return false
}
