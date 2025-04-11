/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"io"
)

type Task interface {
	Run() error
	Validate() error

	SetName(string, string)
	PrintHelp(io.Writer)
}

type Runner struct {
	ConsoleWriter io.Writer
	ErrorWriter   io.Writer

	tasks          map[string]Task
	order          []string
	failedCommands map[string]error
}

// If the task called is not added to the runner,
// this error is returned
var ErrTaskNotFound = errors.New("Task not found")

// NewRunner returns a new Runner structure
func NewRunner() *Runner {
	r := Runner{
		tasks:          make(map[string]Task),
		failedCommands: make(map[string]error),
	}
	return &r
}

// AddTask adds a task to a runner. The runner will run all task
// in the order of which Runner.AddTask is called
func (r *Runner) AddTask(name, envPrefix string, t Task) {
	if _, ok := r.tasks[name]; ok {
		// task exist
		return
	}
	r.order = append(r.order, name)
	r.tasks[name] = t
	t.SetName(name, envPrefix)
}

// RunAll runs all tasks added to the runner.
//
// The flow with force=false calls Task.Validate(), return success if no
// error returned. Otherwise call Task.Run() and execute the task. After
// Task.Run() return, it calls Task.Validate() to check if the task
// successfully finished.
//
// The flow with force=true omits the first call to Task.Validate() and
// calls Task.Run() regarding less if the task hac been done previously.
func (r *Runner) RunAll(force bool) error {
	for _, taskName := range r.order {
		err := r.Run(taskName, force)
		if err != nil {
			log.WithError(err).Errorf("Failed to run task : %s", taskName)
		}
	}
	if len(r.failedCommands) != 0 {
		return errors.New("Failed to run all tasks")
	}
	return nil
}

// PrintAllHelp calls Task.PrintHelp(io.Writer) of all its registered tasks.
// In the order of which they are added with parameter Runner.ConsoleWriter
func (r *Runner) PrintAllHelp() error {
	for taskName := range r.tasks {
		if err := r.PrintHelp(taskName); err != nil {
			return err
		}
	}
	return nil
}

// Run calls Task.Run() for the task added with associated with given name
//
// The flow with force=false calls Task.Validate(), return success if no
// error returned. Otherwise call Task.Run() and execute the task. After
// Task.Run() return, it calls Task.Validate() to check if the task
// successfully finished.
//
// The flow with force=true omits the first call to Task.Validate() and
// calls Task.Run() regarding less if the task hac been done previously.
func (r *Runner) Run(taskName string, force bool) error {
	task, ok := r.tasks[taskName]
	if !ok {
		return ErrTaskNotFound
	}
	if !force {
		printToWriter(r.ConsoleWriter, "", "Validating setup task: "+taskName)
		if err := task.Validate(); err == nil {
			printToWriter(r.ConsoleWriter, "", "Setup task "+taskName+" has been done")
			return nil
		}
	}
	printToWriter(r.ConsoleWriter, "", "Running setup task: "+taskName)
	if err := task.Run(); err != nil {
		printToWriter(r.ConsoleWriter, "Error", "Failed to run task "+taskName)
		retErr := errors.Wrap(err, "Failed to run task "+taskName)
		r.failedCommands[taskName] = retErr
		return retErr
	}
	if err := task.Validate(); err != nil {
		if _, ok := r.failedCommands[taskName]; !ok {
			printToWriter(r.ConsoleWriter, "Error", "Failed to validate task "+taskName)
			retErr := errors.Wrap(err, "Failed to validate task "+taskName)
			r.failedCommands[taskName] = retErr
			return retErr
		}
	}
	printToWriter(r.ConsoleWriter, "", "Setup task finished successfully: "+taskName)
	return nil
}

// PrintHelp calls Task.PrintHelp(io.Writer) for the task added with
// given name with parameter Runner.ConsoleWriter
func (r *Runner) PrintHelp(taskName string) error {
	task, ok := r.tasks[taskName]
	if !ok {
		return ErrTaskNotFound
	}
	task.PrintHelp(r.ConsoleWriter)
	return nil
}

// FailedCommands returns the last command that failed to run
func (r *Runner) FailedCommands() map[string]error {
	return r.failedCommands
}
