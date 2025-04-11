/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package logging

import (
	"fmt"
	"log"
	"os"
)

type LogLevel int

const (
	LogLevelInfo LogLevel = iota
	LogLevelTrace
	LogLevelDebug
)

var currentLogLevel = LogLevelInfo

var Logger *log.Logger

func init() {
	// Initialize the logger
	Logger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	SetLogLevelFromEnv()
}

func SetLogLevel(level LogLevel) {
	currentLogLevel = level
	if Logger != nil {
		Logger.SetPrefix(fmt.Sprintf("%s: ", level.String()))
	}
}

func (level LogLevel) String() string {
	switch level {
	case LogLevelTrace:
		return "TRACE"
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	default:
		return "INFO"
	}
}

func SetLogLevelFromEnv() {
	level := os.Getenv("LOG_LEVEL")
	switch level {
	case "TRACE":
		SetLogLevel(LogLevelTrace)
	case "DEBUG":
		SetLogLevel(LogLevelDebug)
	case "INFO":
		SetLogLevel(LogLevelInfo)
	default:
		SetLogLevel(LogLevelInfo)
	}
	fmt.Println("Current Log Level:", currentLogLevel)
}

// Info logs an informational message
func Info(v ...interface{}) {
	if currentLogLevel >= LogLevelInfo {
		Logger.SetPrefix("INFO: ")
		Logger.Output(2, fmt.Sprintln(v...))
	}
}

// Error logs an error message
func Error(v ...interface{}) {
	Logger.SetPrefix("ERROR: ")
	Logger.Output(2, fmt.Sprintln(v...))
}

// Trace logs a trace message
func Trace(v ...interface{}) {
	if currentLogLevel >= LogLevelTrace {
		Logger.SetPrefix("TRACE: ")
		Logger.Output(2, fmt.Sprintln(v...))
	}
}

// Debug logs a debug message
func Debug(v ...interface{}) {
	if currentLogLevel >= LogLevelDebug {
		Logger.SetPrefix("DEBUG: ")
		Logger.Output(2, fmt.Sprintln(v...))
	}
}

// LogAndReturnError logs an error message and returns the error
func LogAndReturnError(err error, msg string) error {
	Logger.SetPrefix("ERROR: ")
	Logger.Printf("%s: %v", msg, err)
	return fmt.Errorf("%s: %w", msg, err)
}
