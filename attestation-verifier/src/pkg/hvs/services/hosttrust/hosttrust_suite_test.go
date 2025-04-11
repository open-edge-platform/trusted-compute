/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hosttrust

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestHosttrust(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Hosttrust Suite")
}
