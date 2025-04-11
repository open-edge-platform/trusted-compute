/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package common

import (
	"encoding/xml"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
	taModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/ta"
)

func (handler *requestHandlerImpl) GetApplicationMeasurement(manifest *taModel.Manifest, tBootXmMeasurePath string, logDirPath string) (*taModel.Measurement, error) {

	manifestXml, err := xml.Marshal(manifest)
	if err != nil {
		secLog.Errorf("%s common/measure:GetApplicationMeasurement()  Failed to marshal manifest %s", message.InvalidInputBadParam, err.Error())
		return nil, &EndpointError{Message: "Error: Failed to marshal manifest", StatusCode: http.StatusBadRequest}
	}

	// this should probably be done in wml --> if the wml log file is not yet created,
	// 'measure' will fail.  for now, create the file before calling 'measure'.
	if _, err = os.Stat(path.Join(logDirPath, "wml.log")); os.IsNotExist(err) {
		_, err = cos.OpenFileSafe(path.Join(logDirPath, "wml.log"), "", os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() - Unable to open file")
			return nil, &EndpointError{Message: "Error: Unable to open log file", StatusCode: http.StatusInternalServerError}
		}
	}

	// make sure 'measure' is not a symbolic link before executing it
	measureExecutable, err := os.Lstat(tBootXmMeasurePath)
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() - Unable to stat tboot path")
		return nil, &EndpointError{Message: "Error: Unable to stat tboot path", StatusCode: http.StatusInternalServerError}
	}
	if measureExecutable.Mode()&os.ModeSymlink == os.ModeSymlink {
		secLog.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - 'measure' is a symbolic link", message.InvalidInputBadParam)
		return nil, &EndpointError{Message: "Error: Invalid 'measure' file", StatusCode: http.StatusInternalServerError}
	}

	// call /opt/tbootxml/bin/measure and return the xml from stdout
	// 'measure <manifestxml> /'
	cmd := exec.Command(tBootXmMeasurePath, string(manifestXml), "/")
	cmd.Env = append(os.Environ(), "WML_LOG_FILE="+path.Join(logDirPath, "wml.log"))

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Error getting measure output", message.AppRuntimeErr)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	err = cmd.Start()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Failed to run: %s", message.AppRuntimeErr, tBootXmMeasurePath)
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}

	}

	measureBytes, _ := ioutil.ReadAll(stdout)
	err = cmd.Wait()
	if err != nil {
		log.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - %s returned '%s'", message.AppRuntimeErr, tBootXmMeasurePath, string(measureBytes))
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	var measurement taModel.Measurement
	// make sure we got valid xml from measure
	err = xml.Unmarshal(measureBytes, &measurement)
	if err != nil {
		secLog.WithError(err).Errorf("common/measure:GetApplicationMeasurement() %s - Invalid measurement xml : %s", message.AppRuntimeErr, string(measureBytes))
		return nil, &EndpointError{Message: "Error processing request", StatusCode: http.StatusInternalServerError}
	}

	return &measurement, nil
}
