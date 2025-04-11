/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestHvs(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Model Hvs Suite")
}
