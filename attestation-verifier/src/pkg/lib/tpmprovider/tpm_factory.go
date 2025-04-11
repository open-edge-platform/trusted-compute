/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tpmprovider

//
// This interface is responsible for creating instances of TpmProvider.  Generally,
// it provides a 'unit of work' model where consumers create a TpmProvider to interact
// with the physical TPM and then completes that work via TpmProvider.Close().
// In this fashion, long lived services (ex. go-trust-agent http) can retain a reference
// to the TpmFactory and create instances as needed.  This also facilitates unit testing
// and mocks.
//
type TpmFactory interface {
	NewTpmProvider() (TpmProvider, error)
}

type TpmFactoryProvider interface {
	NewTpmFactory() (TpmFactory, error)
}
