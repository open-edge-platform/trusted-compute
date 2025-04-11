/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package intmath

import (
	"testing"
)

func TestMinOf(t *testing.T) {
	type args struct {
		vars []int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "Validate Minimum value",
			args: args{
				vars: []int{6, 1, 2, 3, 4, 5},
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MinOf(tt.args.vars...); got != tt.want {
				t.Errorf("MinOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaxOf(t *testing.T) {
	type args struct {
		vars []int
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "Validate Maximum value",
			args: args{
				vars: []int{1, 2, 3, 4, 5, 6},
			},
			want: 6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MaxOf(tt.args.vars...); got != tt.want {
				t.Errorf("MaxOf() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMin(t *testing.T) {
	type args struct {
		x int64
		y int64
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "Compare Minimum value 1",
			args: args{
				x: 1,
				y: 2,
			},
			want: 1,
		},
		{
			name: "Compare Minimum value 2",
			args: args{
				x: 2,
				y: 1,
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Min(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Min() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMax(t *testing.T) {
	type args struct {
		x int64
		y int64
	}
	tests := []struct {
		name string
		args args
		want int64
	}{
		{
			name: "Compare Maximum value 1",
			args: args{
				x: 1,
				y: 2,
			},
			want: 2,
		},
		{
			name: "Compare Maximum value 2",
			args: args{
				x: 2,
				y: 1,
			},
			want: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Max(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Max() = %v, want %v", got, tt.want)
			}
		})
	}
}
