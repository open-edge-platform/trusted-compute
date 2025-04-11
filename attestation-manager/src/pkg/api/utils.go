/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package api

import (
	"fmt"
	"net/http"
)

// CheckResponseStatus checks the HTTP response status code and returns a boolean indicating success
// and a message describing the status. It is designed to be used for any API call.
func CheckResponseStatus(resp *http.Response) (bool, string) {
	if resp == nil {
		return false, "No response received"
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// Success
		return true, "Success"

	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// Redirection
		return false, fmt.Sprintf("Redirection: %s", resp.Status)

	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Client error
		return false, fmt.Sprintf("Client error: %s", resp.Status)

	case resp.StatusCode >= 500:
		// Server error
		return false, fmt.Sprintf("Server error: %s", resp.Status)

	default:
		// Unexpected status code
		return false, fmt.Sprintf("Unexpected response status: %s", resp.Status)
	}
}
