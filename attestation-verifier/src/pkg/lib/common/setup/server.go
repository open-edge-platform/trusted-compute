/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */
package setup

import (
	"fmt"
	"io"

	commConfig "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/config"
	"github.com/pkg/errors"
)

type ServerSetup struct {
	commConfig.ServerConfig

	SvrConfigPtr  *commConfig.ServerConfig
	ConsoleWriter io.Writer

	DefaultPort int
	envPrefix   string
	commandName string
}

const svrEnvHelpPrompt = "Following environment variables are required for Server setup:"

var svrEnvHelp = map[string]string{
	"SERVER_PORT":                "The Port on which Server Listens to",
	"SERVER_READ_TIMEOUT":        "Request Read Timeout Duration in Seconds",
	"SERVER_READ_HEADER_TIMEOUT": "Request Read Header Timeout Duration in Seconds",
	"SERVER_WRITE_TIMEOUT":       "Request Write Timeout Duration in Seconds",
	"SERVER_IDLE_TIMEOUT":        "Request Idle Timeout in Seconds",
	"SERVER_MAX_HEADER_BYTES":    "Max Length Of Request Header in Bytes ",
}

func (t *ServerSetup) Run() error {
	if t.SvrConfigPtr == nil {
		return errors.New("Pointer to server configuration structure can not be nil")
	}
	if t.Port < 1024 ||
		t.Port > 65535 {
		t.Port = t.DefaultPort
	}
	t.SvrConfigPtr.Port = t.Port
	t.SvrConfigPtr.ReadTimeout = t.ReadTimeout
	t.SvrConfigPtr.ReadHeaderTimeout = t.ReadHeaderTimeout
	t.SvrConfigPtr.WriteTimeout = t.WriteTimeout
	t.SvrConfigPtr.IdleTimeout = t.IdleTimeout
	t.SvrConfigPtr.MaxHeaderBytes = t.MaxHeaderBytes
	return nil
}

func (t *ServerSetup) Validate() error {
	if t.SvrConfigPtr == nil {
		return errors.New("Pointer to server configuration structure can not be nil")
	}
	if t.SvrConfigPtr.Port < 1024 ||
		t.SvrConfigPtr.Port > 65535 {
		return errors.New("Configured port is not valid")
	}
	return nil
}

func (t *ServerSetup) PrintHelp(w io.Writer) {
	PrintEnvHelp(w, svrEnvHelpPrompt, t.envPrefix, svrEnvHelp)
	fmt.Fprintln(w, "")
}

func (t *ServerSetup) SetName(n, e string) {
	t.commandName = n
	t.envPrefix = PrefixUnderscroll(e)
}
