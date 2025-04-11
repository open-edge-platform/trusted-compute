/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package intmath

// MinOf returns the minimum value of a integers passed in
func MinOf(vars ...int) int {
	min := vars[0]

	for _, i := range vars {
		if min > i {
			min = i
		}
	}

	return min
}

// MaxOf returns the minimum value of a integers passed in
func MaxOf(vars ...int) int {
	max := vars[0]

	for _, i := range vars {
		if max < i {
			max = i
		}
	}

	return max
}

// Min returns the minimum of 2 integers
func Min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

// Max returns the maximum of 2 integers
func Max(x, y int64) int64 {
	if x > y {
		return x
	}
	return y
}
