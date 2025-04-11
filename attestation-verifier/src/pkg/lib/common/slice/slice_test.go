/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package slice

import "testing"

func TestContains(t *testing.T) {
	type args struct {
		s    interface{}
		elem interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Validate Contains value",
			args: args{
				s:    []int{1, 2, 3, 4, 5, 6},
				elem: 1,
			},
			want: true,
		},
		{
			name: "Validate does not contain value",
			args: args{
				s:    []int{1, 2, 3, 4, 5, 6},
				elem: 10,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Contains(tt.args.s, tt.args.elem); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}
