/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package log_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/setup"

	"github.com/sirupsen/logrus"
)

// run with: go test ./... -v --count=1 --run
// and inspect standard out or output file
func TestDefaultLog(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)

	log.GetLogger("default").WithField("test", "DefaultLog").Info("Hello")
	log.GetLogger("default").WithField("test", "DefaultLog").Debug("Hello")
	log.GetLogger("default").WithField("test", "DefaultLog").Trace("Hello")
	log.GetLogger("default").WithField("test", "DefaultLog").Warning("Hello")
	log.GetLogger("default").WithField("test", "DefaultLog").Error("Hello")
}

func TestFileLog(t *testing.T) {

	f, err := os.OpenFile("test.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			fmt.Println(err.Error())
		}
	}()

	fileLog := logrus.New()
	fileLog.SetOutput(f)
	fileLog.SetLevel(logrus.TraceLevel)
	fileLog.SetFormatter(&log.LogFormatter{LevelLength: 0})

	err = log.AddLogger("file", fileLog)
	if err != nil {
		fmt.Println(err.Error())
	}
	log.GetLogger("file").Info("Hello")
	log.GetLogger("file").Debug("Hello")
	log.GetLogger("file").Trace("Hello")
	log.GetLogger("file").Warning("Hello")
	log.GetLogger("file").Error("Hello")
}

func TestDuplicatedLog(t *testing.T) {
	var err error
	err = log.AddLogger("abc", logrus.StandardLogger())
	if err != nil {
		fmt.Println(err.Error())
	}
	err = log.AddLogger("abc", logrus.StandardLogger())
	if err != nil {
		fmt.Println(err.Error())
	}
}

func TestPackageNameLog(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetFormatter(&log.LogFormatter{})
	l, lName := log.AddLoggerByPackageName()

	fmt.Println(lName)

	l.WithField("test", "PackageNameLog").Info("Hello")
	l.WithField("test", "PackageNameLog").Debug("Hello")
	l.WithField("test", "PackageNameLog").Trace("Hello")
	l.WithField("test", "PackageNameLog").Warning("Hello")
	l.WithField("test", "PackageNameLog").Error("Hello")
}

func TestSetLogger(t *testing.T) {

	l := log.GetLogger("test")
	l2 := log.GetLogger("test")
	l3 := log.GetLogger("test")

	// shows up in console with level info
	l.WithField("test", "TestSetLogger").Info("Hello")
	l.WithField("test", "TestSetLogger").Debug("Hello")
	l.WithField("test", "TestSetLogger").Trace("Hello")
	l.WithField("test", "TestSetLogger").Warning("Hello")
	l.WithField("test", "TestSetLogger").Error("Hello")

	f, err := os.OpenFile("test1.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		fmt.Println(err.Error())
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			fmt.Println(err.Error())
		}
	}()

	setup.SetLogger("test", logrus.TraceLevel, nil, f, false)

	// These go to a same file
	l.WithField("test", "TestSetLogger").Info("Hello")
	l.WithField("test", "TestSetLogger").Debug("Hello")
	l.WithField("test", "TestSetLogger").Trace("Hello")
	l.WithField("test", "TestSetLogger").Warning("Hello")
	l.WithField("test", "TestSetLogger").Error("Hello")

	l2.WithField("test", "TestSetLogger2").Info("Hello")
	l2.WithField("test", "TestSetLogger2").Debug("Hello")
	l2.WithField("test", "TestSetLogger2").Trace("Hello")
	l2.WithField("test", "TestSetLogger2").Warning("Hello")
	l2.WithField("test", "TestSetLogger2").Error("Hello")

	l3.WithField("test", "TestSetLogger3").Info("Hello")
	l3.WithField("test", "TestSetLogger3").Debug("Hello")
	l3.WithField("test", "TestSetLogger3").Trace("Hello")
	l3.WithField("test", "TestSetLogger3").Warning("Hello")
	l3.WithField("test", "TestSetLogger3").Error("Hello")
}

func TestFormatter(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	// logrus.SetFormatter(&log.LogFormatter{LevelLength: 4, LineFormat: "$lv$[$pid$] $t$: $msg$; $$$$"})
	logrus.SetFormatter(&log.LogFormatter{LevelLength: 4})

	l, _ := log.AddLoggerByPackageName()

	l.Info("Hello")
	l.Debug("Hello")
	l.Trace("Hello")
	l.Warning("Hello")
	l.Error("Hello")

	l.WithField("field", "test").Info("Hello")
	l.WithField("field", "test").Debug("Hello")
	l.WithField("field", "test").Trace("Hello")
	l.WithField("field", "test").Warning("Hello")
	l.WithField("field", "test").Error("Hello")

	l.WithField("field1", "test").WithField("field2", "test").Info("Hello")
	l.WithField("field1", "test").WithField("field2", "test").Debug("Hello")
	l.WithField("field1", "test").WithField("field2", "test").Trace("Hello")
	l.WithField("field1", "test").WithField("field2", "test").Warning("Hello")
	l.WithField("field1", "test").WithField("field2", "test").Error("Hello")
}

func TestFunctionNameLog(t *testing.T) {

	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetFormatter(&log.LogFormatter{})
	l, _ := log.AddLoggerByPackageName()

	MyFunction1 := func() string {
		return log.GetFuncName()
	}

	MyFunction2 := func() string {
		l.WithField("test", "FunctionNameLog").Trace(MyFunction1())
		return log.GetFuncName()
	}

	l.WithField("test", "FunctionNameLog").Info(MyFunction2())
	l.WithField("test", "FunctionNameLog").Debug(MyFunction2())
	l.WithField("test", "FunctionNameLog").Trace(MyFunction2())
	l.WithField("test", "FunctionNameLog").Warning(MyFunction2())
	l.WithField("test", "FunctionNameLog").Error(MyFunction2())

	l.Trace(MyFunction1())
	l.Trace(MyFunction2())
}
