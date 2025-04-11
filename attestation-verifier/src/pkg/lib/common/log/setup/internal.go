/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"errors"
	"io"
	"os"
	"sync"

	log "github.com/sirupsen/logrus"
)

var addLoggerMux sync.Mutex
var loggers = make(map[string]*log.Entry)

var ErrLoggerExists = errors.New("Logger already added")

func AddLogger(name, field string, l *log.Logger) error {
	if _, ok := loggers[name]; ok {
		return ErrLoggerExists
	}
	addLoggerMux.Lock()
	if _, ok := loggers[name]; !ok {
		loggers[name] = l.WithField(field, name).WithField("pid", os.Getpid())
	}
	addLoggerMux.Unlock()
	return nil
}

func GetLogger(name string) *log.Entry {
	if ret, ok := loggers[name]; ok {
		return ret
	}
	err := AddLogger(name, "name", log.New())
	if err != nil {
		log.WithError(err).Error("failed to add logger")
	}

	ret, _ := loggers[name]
	return ret
}

func SetLogger(name string, lv log.Level, fmt log.Formatter, out io.Writer, rc bool) {
	l := GetLogger(name).Logger
	if fmt != nil {
		l.SetFormatter(fmt)
	}
	if out != nil {
		l.SetOutput(out)
	}
	l.SetLevel(lv)
	l.SetReportCaller(rc)
}
