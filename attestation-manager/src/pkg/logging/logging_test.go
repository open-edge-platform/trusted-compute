package logging

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestSetLogLevel(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", log.LstdFlags)

	SetLogLevel(LogLevelDebug)
	if currentLogLevel != LogLevelDebug {
		t.Errorf("expected %v, got %v", LogLevelDebug, currentLogLevel)
	}
	if !strings.HasPrefix(Logger.Prefix(), "DEBUG: ") {
		t.Errorf("expected prefix %v, got %v", "DEBUG: ", Logger.Prefix())
	}
}

func TestSetLogLevelFromEnv(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", log.LstdFlags)

	os.Setenv("LOG_LEVEL", "TRACE")
	SetLogLevelFromEnv()
	if currentLogLevel != LogLevelTrace {
		t.Errorf("expected %v, got %v", LogLevelTrace, currentLogLevel)
	}
	if !strings.HasPrefix(Logger.Prefix(), "TRACE: ") {
		t.Errorf("expected prefix %v, got %v", "TRACE: ", Logger.Prefix())
	}
	os.Unsetenv("LOG_LEVEL")
}

func TestInfo(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", 0)

	SetLogLevel(LogLevelInfo)
	Info("test info message")

	logOutput := buf.String()
	expectedMessage := "INFO: test info message\n"

	if !strings.Contains(logOutput, expectedMessage) {
		t.Errorf("expected log message to contain %v, got %v", expectedMessage, logOutput)
	}
}

func TestError(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", 0)

	Error("test error message")

	logOutput := buf.String()
	expectedMessage := "ERROR: test error message\n"

	if !strings.Contains(logOutput, expectedMessage) {
		t.Errorf("expected log message to contain %v, got %v", expectedMessage, logOutput)
	}
}

func TestTrace(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", 0)

	SetLogLevel(LogLevelTrace)
	Trace("test trace message")

	logOutput := buf.String()
	expectedMessage := "TRACE: test trace message\n"

	if !strings.Contains(logOutput, expectedMessage) {
		t.Errorf("expected log message to contain %v, got %v", expectedMessage, logOutput)
	}
}

func TestDebug(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", 0)

	SetLogLevel(LogLevelDebug)
	Debug("test debug message")

	logOutput := buf.String()
	expectedMessage := "DEBUG: test debug message\n"

	if !strings.Contains(logOutput, expectedMessage) {
		t.Errorf("expected log message to contain %v, got %v", expectedMessage, logOutput)
	}
}

func TestLogAndReturnError(t *testing.T) {
	var buf bytes.Buffer
	Logger = log.New(&buf, "", 0)

	err := LogAndReturnError(os.ErrNotExist, "file not found")

	logOutput := buf.String()
	expectedLogMessage := "ERROR: file not found: file does not exist\n"
	expectedErrorMessage := "file not found: file does not exist"

	if !strings.Contains(logOutput, expectedLogMessage) {
		t.Errorf("expected log message to contain %v, got %v", expectedLogMessage, logOutput)
	}
	if err.Error() != expectedErrorMessage {
		t.Errorf("expected error message to be %v, got %v", expectedErrorMessage, err.Error())
	}
}