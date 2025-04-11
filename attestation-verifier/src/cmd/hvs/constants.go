/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

const (
	ServiceUserName = "hvs"
	ServiceDir      = "hvs/"
	LogDir          = "/var/log/" + ServiceDir
	LogFile         = LogDir + ServiceUserName + ".log"
	HttpLogFile     = LogDir + ServiceUserName + "-http.log"
	SecurityLogFile = LogDir + ServiceUserName + "-security.log"
)
