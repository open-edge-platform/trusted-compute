/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package model

import "encoding/xml"

// <tpm_quote_response>
//     <timestamp>1569264156635</timestamp>
//     <errorCode>0</errorCode>
//     <errorMessage>OK</errorMessage>
//     <aik>MIIDSjCCAbKgAwIBAgIGAWz...</aik>
//     <quote>AIv/VENHgBgAIgALUiWzd9...=</quote>
//     <eventLog>PG1lYXN1cmVMb2c+PHR4dD48dHh0U3RhdH...=</eventLog>
//     <tcbMeasurements>
//         <tcbMeasurements>&lt;?xml version="1.0" encoding="UTF-8" standalone="yes"?>&lt;Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Workload_Flavor_v2.0" Uuid="b13b405b-97a7-4480-a2e7-eea01f9799ce" DigestAlg="SHA384">&lt;CumulativeHash>000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000&lt;/CumulativeHash>&lt;/Measurement></tcbMeasurements>
// 			<...>
//     </tcbMeasurements>
//     <selectedPcrBanks>
//         <selectedPcrBanks>SHA1</selectedPcrBanks>
//         <selectedPcrBanks>SHA256</selectedPcrBanks>
//     </selectedPcrBanks>
//     <isTagProvisioned>false</isTagProvisioned>
// </tpm_quote_response>
type TpmQuoteResponse struct {
	XMLName         xml.Name `xml:"tpm_quote_response"`
	TimeStamp       int64    `xml:"timestamp"`
	ErrorCode       int      `xml:"errorCode"`
	ErrorMessage    string   `xml:"errorMessage"`
	Aik             string   `xml:"aik"`
	Quote           string   `xml:"quote"`
	EventLog        string   `xml:"eventLog"`
	ImaLogs         string   `xml:"imaLogs"`
	TcbMeasurements struct {
		XMLName         xml.Name `xml:"tcbMeasurements"`
		TcbMeasurements []string `xml:"tcbMeasurements"`
	}
	SelectedPcrBanks struct {
		XMLName          xml.Name `xml:"selectedPcrBanks"`
		SelectedPcrBanks []string `xml:"selectedPcrBanks"`
	}
	IsTagProvisioned bool   `xml:"isTagProvisioned"`
	AssetTag         string `xml:"assetTag,omitempty"`
}
