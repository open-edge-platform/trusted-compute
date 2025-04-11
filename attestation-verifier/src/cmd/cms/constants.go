/*
 *  Copyright (C) 2025 Intel Corporation
 *  SPDX-License-Identifier: BSD-3-Clause
 */

package main

const (
	LogDir          = "/var/log/cms/"
	LogFile         = LogDir + ServiceUserName + ".log"
	SecurityLogFile = LogDir + ServiceUserName + "-security.log"
	HTTPLogFile     = LogDir + ServiceUserName + "-http.log"
	ServiceUserName = "cms"
)
