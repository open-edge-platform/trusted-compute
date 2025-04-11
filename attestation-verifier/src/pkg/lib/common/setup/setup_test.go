/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package setup

import (
	"io"
	"reflect"
	"testing"

	"github.com/pkg/errors"
)

var testConfigMap = map[string]string{
	"TEST_ARG_KEY_ONE":   "test-arg-val-one",
	"TEST_ARG_KEY_TWO":   "test-arg-val-two",
	"TEST_ARG_KEY_THREE": "test-arg-val-three",
}

type testTaskOne struct {
	Arg string

	hasConfig bool
	hasRun    bool
}

func (t *testTaskOne) Run() error {
	t.hasRun = true
	return nil
}

func (t *testTaskOne) Validate() error {
	if t.hasRun &&
		t.Arg == "test-arg-val-one" {
		return nil
	}
	return errors.New("validation failed")
}

type testTaskTwo struct {
	Arg string

	hasConfig bool
	hasRun    bool
}

func (t *testTaskTwo) Run() error {
	t.hasRun = true
	return nil
}

func (t *testTaskTwo) Validate() error {
	if t.hasRun &&
		t.Arg == "test-arg-val-two" {
		return nil
	}
	return errors.New("validation failed")
}

type testTaskThree struct {
	Arg string

	hasConfig bool
	hasRun    bool
}

func (t *testTaskThree) Run() error {
	t.hasRun = true
	return errors.New("Run error case")
}

func (t *testTaskThree) Validate() error {
	if t.hasRun &&
		t.Arg == "test-arg-val-three" {
		return nil
	}
	return errors.New("validation failed")
}

type testTaskFour struct {
	Arg string

	hasConfig bool
	hasRun    bool
}

func (t *testTaskFour) Run() error {
	t.hasRun = true
	return nil
}

func (t *testTaskFour) Validate() error {
	if t.hasRun &&
		t.Arg == "test-arg-val-four" {
		return nil
	}
	return errors.New("validation failed")
}

func (t *testTaskOne) PrintHelp(w io.Writer)   {}
func (t *testTaskTwo) PrintHelp(w io.Writer)   {}
func (t *testTaskThree) PrintHelp(w io.Writer) {}
func (t *testTaskFour) PrintHelp(w io.Writer)  {}

func (t *testTaskOne) SetName(string, string)   {}
func (t *testTaskTwo) SetName(string, string)   {}
func (t *testTaskThree) SetName(string, string) {}
func (t *testTaskFour) SetName(string, string)  {}

func TestSetupRunner(t *testing.T) {
	runner := NewRunner()
	runner.AddTask("task-1", "", &testTaskOne{
		Arg: testConfigMap["TEST_ARG_KEY_ONE"],
	})
	runner.AddTask("task-1", "", &testTaskTwo{
		Arg: testConfigMap["TEST_ARG_KEY_TWO"],
	})
	if err := runner.RunAll(true); err != nil {
		t.Error("Failed to run all tasks:", err.Error())
	}

	if err := runner.RunAll(false); err != nil {
		t.Error("Failed to run all tasks:", err.Error())
	}

	// Error case 1 - Run error

	runner = NewRunner()
	runner.AddTask("task-1", "", &testTaskThree{
		Arg: testConfigMap["TEST_ARG_KEY_THREE"],
	})
	if err := runner.RunAll(true); err == nil {
		t.Error("Failed to run all tasks:", err.Error())
	}

	// Error case 2 - Validate error

	runner = NewRunner()
	runner.AddTask("task-1", "", &testTaskTwo{
		Arg: testConfigMap["TEST_ARG_KEY_FOUR"],
	})
	if err := runner.RunAll(true); err == nil {
		t.Error("Failed to run all tasks:", err.Error())
	}

	if err := runner.RunAll(false); err == nil {
		t.Error("Failed to run all tasks:", err.Error())
	}

}

func TestRunner_PrintAllHelp(t *testing.T) {
	type fields struct {
		ConsoleWriter  io.Writer
		ErrorWriter    io.Writer
		tasks          map[string]Task
		order          []string
		failedCommands map[string]error
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Validate print all help",
			fields: fields{
				tasks: map[string]Task{"task1": &testTaskOne{}},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Runner{
				ConsoleWriter:  tt.fields.ConsoleWriter,
				ErrorWriter:    tt.fields.ErrorWriter,
				tasks:          tt.fields.tasks,
				order:          tt.fields.order,
				failedCommands: tt.fields.failedCommands,
			}
			if err := r.PrintAllHelp(); (err != nil) != tt.wantErr {
				t.Errorf("Runner.PrintAllHelp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunner_FailedCommands(t *testing.T) {
	type fields struct {
		ConsoleWriter  io.Writer
		ErrorWriter    io.Writer
		tasks          map[string]Task
		order          []string
		failedCommands map[string]error
	}
	tests := []struct {
		name   string
		fields fields
		want   map[string]error
	}{
		{
			name: "Validate failed commands",
			fields: fields{failedCommands: map[string]error{
				"task1": nil,
			}},
			want: map[string]error{
				"task1": nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Runner{
				ConsoleWriter:  tt.fields.ConsoleWriter,
				ErrorWriter:    tt.fields.ErrorWriter,
				tasks:          tt.fields.tasks,
				order:          tt.fields.order,
				failedCommands: tt.fields.failedCommands,
			}
			if got := r.FailedCommands(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Runner.FailedCommands() = %v, want %v", got, tt.want)
			}
		})
	}
}
