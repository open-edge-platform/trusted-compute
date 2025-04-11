/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package log

import (
	"runtime"
	"strings"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/setup"

	log "github.com/sirupsen/logrus"
)

var ErrLoggerExists = setup.ErrLoggerExists

const (
	unknownLoggerName  = "unknown"
	DefaultLoggerName  = "default"
	SecurityLoggerName = "security"
)

var defaultLogger *log.Entry
var securityLogger *log.Entry

func init() {
	err := setup.AddLogger(DefaultLoggerName, "name", log.StandardLogger())
	if err != nil {
		log.WithError(err).Error("failed to add logger")
	}

	err = setup.AddLogger(SecurityLoggerName, "name", log.New())
	if err != nil {
		log.WithError(err).Error("failed to add logger")
	}

	err = setup.AddLogger(unknownLoggerName, "package", log.StandardLogger())
	if err != nil {
		log.WithError(err).Error("failed to add logger")
	}

}

func AddLogger(name string, l *log.Logger) error {
	return setup.AddLogger(name, "name", l)
}

func AddLoggerByPackageName() (*log.Entry, string) {
	pc := make([]uintptr, 2)
	runtime.Callers(2, pc)
	f := runtime.FuncForPC(pc[0])
	pkgName := strings.Split(f.Name(), ".")[0]
	err := setup.AddLogger(pkgName, "package", log.StandardLogger())
	if err != nil {
		log.WithError(err).Error("failed to add logger")
	}

	return setup.GetLogger(pkgName), pkgName
}

func GetLogger(name string) *log.Entry {
	if name == "" {
		return setup.GetLogger(unknownLoggerName)
	}
	return setup.GetLogger(name)
}

func GetDefaultLogger() *log.Entry {
	if defaultLogger == nil {
		defaultLogger = setup.GetLogger(DefaultLoggerName)
	}
	return defaultLogger
}

func GetSecurityLogger() *log.Entry {
	if securityLogger == nil {
		securityLogger = setup.GetLogger(SecurityLoggerName)
	}
	return securityLogger
}

// GetFuncName returns the name of the calling function or code block
func GetFuncName() string {
	pc := make([]uintptr, 15)
	n := runtime.Callers(2, pc)
	frames := runtime.CallersFrames(pc[:n])
	frame, _ := frames.Next()
	return frame.Function
}
