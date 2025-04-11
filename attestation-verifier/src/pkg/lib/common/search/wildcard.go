/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package search

func create2DArray(m, n int) [][]bool {
	var arr [][]bool
	for i := 0; i <= m; i++ {
		arr = append(arr, make([]bool, n+1))
	}

	return arr
}

func WildcardMatched(s, p string) bool {
	if len(s) == 0 && len(p) == 0 {
		return true
	}
	if len(s) > 0 && len(p) == 0 {
		return false
	}

	dp := create2DArray(len(s), len(p))
	dp[0][0] = true
	for i := 1; i <= len(p); i++ {
		if p[i-1] != '*' {
			dp[0][i] = false
		} else {
			dp[0][i] = dp[0][i-1]
		}
	}

	for i := 1; i <= len(s); i++ {
		for j := 1; j <= len(p); j++ {
			if s[i-1] == p[j-1] || p[j-1] == '?' {
				dp[i][j] = dp[i-1][j-1]
			} else if p[j-1] == '*' {
				dp[i][j] = dp[i-1][j] || dp[i][j-1]
			} else {
				dp[i][j] = false
			}
		}
	}

	return dp[len(s)][len(p)]

}
