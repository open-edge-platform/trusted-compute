/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package taskstage

import (
	"context"
)

type Stage int

const (
	DoNotUse Stage = iota
	FlavorVerifyQueued
	FlavorVerifyStarted
	GetHostDataQueued
	GetHostDataStarted
	ReportCreationStarted
	ReportCreationDone
)

type key int

const stageKey = 0

func NewContext(ctx context.Context, stg Stage) context.Context {
	return context.WithValue(ctx, stageKey, &stg)
}

func FromContext(ctx context.Context) (Stage, bool) {
	if stg, ok := ctx.Value(stageKey).(*Stage); ok {
		return *stg, ok
	}
	return DoNotUse, false

}

func StoreInContext(ctx context.Context, stg Stage) bool {
	if s, ok := ctx.Value(stageKey).(*Stage); !ok {
		return ok
	} else {
		*s = stg
		return true
	}
}
