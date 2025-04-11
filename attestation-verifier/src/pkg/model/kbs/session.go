/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package kbs

import (
	"time"
)

type KeyTransferSession struct {
	SWK               []byte `json:"swk"`
	SessionId         string `json:"sessionid"`
	ClientCertHash    string `json:"clientcerthash"`
	Stmlabel          string `json:"stmlabel"`
	SessionExpiryTime time.Time
}

type ChallengeRequest struct {
	Challenge     string        `json:"challenge,omitempty"`
	ChallengeType string        `json:"challenge_type,omitempty"`
	Faults        []Fault       `json:"faults"`
	Link          ChallengeLink `json:"link,omitempty"`
	Operation     string        `json:"operation"`
	Status        string        `json:"status"`
}

type NotFoundResponse struct {
	Faults    []Fault `json:"faults"`
	Operation string  `json:"operation"`
	Status    string  `json:"status"`
}

type Fault struct {
	Message string `json:"message,omitempty"`
	Type    string `json:"type"`
}

type ChallengeLink struct {
	ChallengeReply ChallengeReplyToNode `json:"challenge-replyto,omitempty"`
}

type ChallengeReplyToNode struct {
	Href   string `json:"href,omitempty"`
	Method string `json:"method,omitempty"`
}

type QuoteVerifyAttributes struct {
	Message                string `json:"Message"`
	ChallengeKeyType       string `json:"ChallengeKeyType"`
	ChallengeRsaPublicKey  string `json:"ChallengeRsaPublicKey"`
	EnclaveIssuer          string `json:"EnclaveIssuer"`
	EnclaveIssuerProductID string `json:"EnclaveIssuerProdID"`
	EnclaveMeasurement     string `json:"EnclaveMeasurement"`
	IsvSvn                 string `json:"IsvSvn"`
	TCBLevel               string `json:"TcbLevel"`
}

type QuoteVerifyResponse struct {
	Created []QuoteVerifyAttributes `json:"created,omitempty"`
}

type SessionResponseAttributes struct {
	SessionData Data   `json:"data"`
	Operation   string `json:"operation"`
	Status      string `json:"status"`
}

type Data struct {
	SWK           []byte `json:"swk,omitempty"`
	AlgorithmType string `json:"type,omitempty"`
}

type SessionManagementAttributes struct {
	ChallengeType string `json:"challenge_type"`
	Challenge     string `json:"challenge"`
	Quote         string `json:"quote"`
}
