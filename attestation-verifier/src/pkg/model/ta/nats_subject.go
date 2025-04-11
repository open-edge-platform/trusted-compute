/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "fmt"

const (
	NatsHostInfoRequest               = "host-info-request"
	NatsQuoteRequest                  = "quote-request"
	NatsAikRequest                    = "aik-request"
	NatsDeployManifestRequest         = "deploy-manifest"
	NatsDeployAssetTagRequest         = "deploy-asset-tag"
	NatsBkRequest                     = "get-binding-certificate"
	NatsApplicationMeasurementRequest = "application-measurement-request"
	NatsVersionRequest                = "version-request"
	NatsSendImaFileList               = "send-ima-filelist-request"
)

func CreateSubject(id, request string) string {
	return fmt.Sprintf("trust-agent.%s.%s", id, request)
}
