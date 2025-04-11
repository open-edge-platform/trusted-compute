/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"testing"
)

func TestGetIntermediateCAs(t *testing.T) {
	intermediateCa := GetIntermediateCAs()
	if !(intermediateCa[0] == Tls && intermediateCa[1] == TlsClient && intermediateCa[2] == Signing) {
		t.Errorf("Error fetching cert types for intermediate ca")
	}
}

func TestGetCaAttribs(t *testing.T) {
	caAttrib := GetCaAttribs("TLS", CertStoreMap)
	CN := "CMS TLS CA"
	if !(caAttrib.CommonName == CN) {
		t.Errorf("Error fetching common name of issuing cs")
	}
	caAttribs := GetCaAttribs("unknown", CertStoreMap)
	if !(caAttribs == CaAttrib{}) {
		t.Errorf("Empty CaAttrib to be returned as unknown issuing ca given")
	}
}
