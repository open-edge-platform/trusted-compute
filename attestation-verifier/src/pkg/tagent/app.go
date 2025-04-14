/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tagent

import (
	"bytes"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/tpmprovider"

	"crypto/x509"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/clients/hvsclient"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/message"
	commLogInt "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/setup"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/utils"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/hostinfo"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/config"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/eventlog"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/tagent/util"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	cos "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/os"
)

var (
	log           = commLog.GetDefaultLogger()
	secLog        = commLog.GetSecurityLogger()
	errInvalidCmd = errors.New("Invalid input after command")
)

type App struct {
	HomeDir        string
	ConfigDir      string
	LogDir         string
	ExecutablePath string
	ExecLinkPath   string
	RunDirPath     string

	config *config.TrustAgentConfiguration

	ConsoleWriter io.Writer
	ErrorWriter   io.Writer
	LogWriter     io.Writer
	SecLogWriter  io.Writer
	HTTPLogWriter io.Writer
}

func (a *App) getHostInfoJSON() ([]byte, error) {

	hostInfo := hostinfo.NewHostInfoParser().Parse()

	// serialize to json
	hostInfoJSON, err := json.MarshalIndent(hostInfo, "", "  ")
	if err != nil {
		return nil, errors.Wrap(err, "Error serializing hostinfo to JSON")
	}

	return hostInfoJSON, nil
}

func (a *App) updatePlatformInfo() error {
	log.Trace("main:updatePlatformInfo() Entering")
	defer log.Trace("main:updatePlatformInfo() Leaving")

	hostInfoJSON, err := a.getHostInfoJSON()
	if err != nil {
		return err
	}

	// make sure the system-info directory exists
	_, err = os.Stat(constants.SystemInfoDir)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while checking the existence of %s", constants.SystemInfoDir)
	}

	// create the 'platform-info' file
	f, err := cos.OpenFileSafe(constants.PlatformInfoFilePath, "", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while creating %s", constants.PlatformInfoFilePath)
	}
	defer func() {
		derr := f.Close()
		if derr != nil {
			log.WithError(derr).Warn("Error closing file")
		}
	}()

	_, err = f.Write(hostInfoJSON)
	if err != nil {
		return errors.Wrapf(err, "main:updatePlatformInfo() Error while writing into File: %s", constants.PlatformInfoFilePath)
	}

	log.Debug("main:updatePlatformInfo() Successfully updated platform-info")
	return nil
}

func (a *App) getEventLogJSON() ([]byte, error) {

	secLog.Debugf("%s main:getEventLogJSON() Running code to read EventLog", message.SU)
	evParser := eventlog.NewEventLogParser()
	pcrEventLogs, err := evParser.GetEventLogs()
	if err != nil {
		return nil, errors.Wrap(err, "main:getEventLogJSON() There was an error while collecting PCR Event Log Data")
	}

	if pcrEventLogs == nil {
		return nil, errors.New("main:getEventLogJSON() No event logs were collected")
	}

	jsonData, err := json.Marshal(pcrEventLogs)
	if err != nil {
		return nil, errors.Wrap(err, "main:getEventLogJSON() There was an error while serializing PCR Event Log Data")
	}

	return jsonData, nil
}

func (a *App) updateMeasureLog() error {
	log.Trace("main:updateMeasureLog() Entering")
	defer log.Trace("main:updateMeasureLog() Leaving")

	jsonData, err := a.getEventLogJSON()
	if err != nil {
		return err
	}

	jsonReport, err := cos.OpenFileSafe(constants.MeasureLogFilePath, "", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return errors.Wrapf(err, "main:updateMeasureLog() There was an error while opening %s", constants.MeasureLogFilePath)
	}
	defer func() {
		derr := jsonReport.Close()
		if derr != nil {
			log.WithError(derr).Warnf("main:updateMeasureLog() There was an error closing %s", constants.MeasureLogFilePath)
		}
	}()

	_, err = jsonReport.Write(jsonData)
	if err != nil {
		return errors.Wrapf(err, "main:updateMeasureLog() There was an error while writing in %s", constants.MeasureLogFilePath)
	}

	log.Debug("main:updateMeasureLog() Successfully updated measure-log.json")
	return nil
}

func (a *App) consoleWriter() io.Writer {
	if a.ConsoleWriter != nil {
		return a.ConsoleWriter
	}
	return os.Stdout
}

func (a *App) errorWriter() io.Writer {
	if a.ErrorWriter != nil {
		return a.ErrorWriter
	}
	return os.Stderr
}

func (a *App) secLogWriter() io.Writer {
	if a.SecLogWriter != nil {
		return a.SecLogWriter
	}
	return os.Stdout
}

func (a *App) logWriter() io.Writer {
	if a.LogWriter != nil {
		return a.LogWriter
	}
	return os.Stderr
}

func (a *App) httpLogWriter() io.Writer {
	if a.HTTPLogWriter != nil {
		return a.HTTPLogWriter
	}
	return os.Stderr
}

func (a *App) configuration() *config.TrustAgentConfiguration {
	if a.config != nil {
		return a.config
	}
	c, err := config.LoadConfiguration()
	if err == nil {
		a.config = c
		return a.config
	}
	return nil
}

func (a *App) configureLogs(stdOut, logFile bool) error {
	var ioWriterDefault io.Writer
	ioWriterDefault = a.logWriter()
	if stdOut {
		if logFile {
			ioWriterDefault = io.MultiWriter(os.Stdout, a.logWriter())
		} else {
			ioWriterDefault = os.Stdout
		}
	}
	ioWriterSecurity := io.MultiWriter(ioWriterDefault, a.secLogWriter())

	logConfig := a.config.Logging
	lv, err := logrus.ParseLevel(logConfig.Level)
	if err != nil {
		return errors.Wrap(err, "Failed to initiate loggers. Invalid log level: "+logConfig.Level)
	}
	f := commLog.LogFormatter{MaxLength: logConfig.MaxLength}
	commLogInt.SetLogger(commLog.DefaultLoggerName, lv, &f, ioWriterDefault, false)
	commLogInt.SetLogger(commLog.SecurityLoggerName, lv, &f, ioWriterSecurity, false)

	secLog.Info(message.LogInit)
	log.Info(message.LogInit)
	return nil
}

func (a *App) start() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl start tagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStart, constants.ServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) stop() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl stop tagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStop, constants.ServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func (a *App) status() error {
	fmt.Fprintln(a.consoleWriter(), `Forwarding to "systemctl status tagent"`)
	systemctl, err := exec.LookPath("systemctl")
	if err != nil {
		return err
	}
	cmd := exec.Command(systemctl, constants.SystemctlStatus, constants.ServiceName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

// Function to set group ownership of root owned file
func updateGroupOwnership(fileName string, rootUserName string, gid int) {
	log.Trace("app:updateGroupOwnership() Entering")
	defer log.Trace("app:updateGroupOwnership() Leaving")

	rootUser, err := user.Lookup(rootUserName)
	if err != nil {
		log.WithError(err).Warnf("app:updateGroupOwnership() Could not find user %s", rootUserName)
		return
	}

	// get root user uid
	uid, err := strconv.ParseUint(rootUser.Uid, 10, 32)
	if err != nil {
		log.WithError(err).Warnf("app:updateGroupOwnership() Could not parse user uid '%s'", rootUser.Uid)
		return
	}

	err = os.Chown(fileName, int(uid), gid)
	if err != nil {
		log.WithError(err).Warnf("app:updateGroupOwnership() Error while configuring group ownership of %s", fileName)
		return
	}
}

func (a *App) Run(args []string) error {

	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Panic occurred: %+v", err)
			log.Error(string(debug.Stack()))
		}
	}()

	if len(os.Args) <= 1 {
		fmt.Fprintf(os.Stderr, "Invalid arguments: %s\n", os.Args)
		a.printUsage()
		os.Exit(1)
	}

	if err := validation.ValidateStrings(os.Args); err != nil {
		secLog.WithError(err).Errorf("%s main:main() Invalid arguments", message.InvalidInputBadParam)
		fmt.Fprintln(os.Stderr, "Invalid arguments")
		a.printUsage()
		os.Exit(1)
	}

	currentUser, _ := user.Current()

	cmd := os.Args[1]
	switch cmd {
	case "version", "--version", "-v":
		a.printVersion()
		return nil
	case "hostinfo":

		if currentUser.Username != constants.RootUserName {
			fmt.Printf("'tagent hostinfo' must be run as root, not user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		hostInfoJSON, err := a.getHostInfoJSON()
		if err != nil {
			fmt.Printf("%+v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(hostInfoJSON))

	case "eventlog":

		if currentUser.Username != constants.RootUserName {
			fmt.Printf("'tagent eventlog' must be run as root, not user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		eventLogJSON, err := a.getEventLogJSON()
		if err != nil {
			fmt.Printf("%+v\n", err)
			os.Exit(1)
		}

		var out bytes.Buffer
		err = json.Indent(&out, eventLogJSON, "", "  ")
		if err != nil {
			fmt.Printf("%+v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(out.Bytes()))

	case "init":
		//
		// The trust-agent service requires files like platform-info and eventLog.xml to be up to
		// date.  It also needs to run as the tagent user for security reasons.
		//
		// 'tagent init' is run as root (as configured in 'tagent_init.service') to generate
		// those files and own the files by tagent user.  The 'tagent.service' is configured
		// to 'Require' 'tagent_init.service' so that running 'systemctl start tagent' will
		// always run 'tagent_init'.
		//
		if currentUser.Username != constants.RootUserName {
			fmt.Printf("'tagent start' must be run as root, not  user '%s'\n", currentUser.Username)
			os.Exit(1)
		}

		c := a.configuration()
		if c == nil {
			return errors.New("Failed to load configuration")
		}
		// initialize log
		if err := a.configureLogs(c.Logging.EnableStdout, true); err != nil {
			return err
		}

		err := a.updatePlatformInfo()
		if err != nil {
			log.WithError(err).Warn("main:main() Error while creating platform-info")
		}

		err = a.updateMeasureLog()
		if err != nil {
			log.WithError(err).Warn("main:main() Error while creating measure-log.json")
		}

		// tagent container is run as root user, skip user look up for tagent when run as a container
		if utils.IsContainerEnv() {
			return nil
		}

		tagentUser, err := user.Lookup(constants.TagentUserName)
		if err != nil {
			log.Errorf("main:main() Could not find user '%s'", constants.TagentUserName)
			os.Exit(1)
		}

		uid, err := strconv.ParseUint(tagentUser.Uid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user uid '%s'", tagentUser.Uid)
			os.Exit(1)
		}

		gid, err := strconv.ParseUint(tagentUser.Gid, 10, 32)
		if err != nil {
			log.Errorf("main:main() Could not parse tagent user gid '%s'", tagentUser.Gid)
			os.Exit(1)
		}

		if c.ImaMeasureEnabled {
			// update group ownership of /sys/kernel/security/ima/ascii_runtime_measurements to provide read access to tagent for ima-log
			updateGroupOwnership(constants.AsciiRuntimeMeasurementFilePath, constants.RootUserName, int(gid))
		}

		// take ownership of all the files in /opt/trustagent before forking the
		// tagent service
		_ = filepath.Walk(constants.InstallationDir, func(fileName string, info os.FileInfo, err error) error {
			//log.Infof("Owning file %s", fileName)
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
				return errors.Wrapf(err, "main:main() Could not own file '%s'", fileName)
			}

			return nil
		})

		_ = filepath.Walk(constants.LogDir, func(fileName string, info os.FileInfo, err error) error {
			err = os.Chown(fileName, int(uid), int(gid))
			if err != nil {
				return errors.Wrapf(err, "main:main() Could not own file '%s'", fileName)
			}

			return nil
		})

		fmt.Println("tagent 'init' completed successful")

	case "startService":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.startServer()
	case "start":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.start()
	case "stop":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.stop()
	case "status":
		if len(args) != 2 {
			return errInvalidCmd
		}
		return a.status()

	case "setup":
		if err := a.setup(args[1:]); err != nil {
			if errors.Cause(err) == setup.ErrTaskNotFound {
				a.printUsageWithError(err)
			} else {
				fmt.Fprintln(a.errorWriter(), err.Error())
			}
			return err
		}

	case "fetch-ekcert-with-issuer":
		var err error
		if len(args) == 2 {
			tpmOwnerSecret := os.Getenv(constants.EnvTPMOwnerSecret)
			if len(tpmOwnerSecret) == 0 {
				err = fetchEndorsementCert("")
			} else {
				if len(tpmOwnerSecret) != 40 {
					return errors.New("Owner secret must be 40 characters long")
				}
				if validation.ValidateHexString(tpmOwnerSecret) != nil {
					return errors.New("Owner secret must be hex string")
				}
				err = fetchEndorsementCert(tpmprovider.HEX_PREFIX + tpmOwnerSecret)
			}
		} else {
			a.printUsage()
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "main:main() Error while running trustagent fetch-ekcert-with-issuer %s\n", err.Error())
			os.Exit(1)
		}
	case "uninstall":
		err := a.uninstall()
		if err != nil {
			fmt.Fprintf(os.Stderr, "main:main() Error while running uninstalling trustagent %+v\n", err)
			os.Exit(1)
		}

	case "ima-load-policy":
		if currentUser.Username != constants.RootUserName {
			fmt.Fprintln(os.Stderr, "'tagent ima-load-policy' must be run as root, not user '%s'", currentUser.Username)
			os.Exit(1)
		}

		imaPolicy, err := os.ReadFile(constants.ImaPolicyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading IMA policy from %s: %+v", constants.ImaPolicyPath, err)
			os.Exit(1)
		}

		retryCount := 5
		for i := 0; i < retryCount; i++ {
			err = os.WriteFile("/opt/ima/policy", imaPolicy, 0644)
			if err == nil {
				fmt.Println("IMA policy loaded successfully")
				return nil
			}
			log.Tracef("Retrying to write IMA policy to /sys/kernel/security/ima/policy (%d/%d)", i+1, retryCount)
			time.Sleep(2 * time.Second)
		}

		searchString := "/opt/verifier/"

		fileContent, err := os.ReadFile(constants.AsciiRuntimeMeasurementFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file %s: %+v\n", constants.AsciiRuntimeMeasurementFilePath, err)
			os.Exit(1)
		}

		if strings.Contains(string(fileContent), searchString) {
			fmt.Printf("The file %s contains the entry: %s\n", constants.AsciiRuntimeMeasurementFilePath, searchString)
			fmt.Println("IMA policy already loaded successfully")
		} else {
			fmt.Printf("The file %s does not contain the entry: %s\n", constants.AsciiRuntimeMeasurementFilePath, searchString)
			os.Exit(1)
		}

		return nil

	case "help", "-h", "--help":
		a.printUsage()

	default:
		fmt.Fprintf(os.Stderr, "Invalid option: '%s'\n\n", cmd)
		a.printUsage()
	}
	return nil
}

func fetchEndorsementCert(assetTagSecret string) error {
	log.Trace("main:fetchEndorsementCert() Entering")
	defer log.Trace("main:fetchEndorsementCert() Leaving")
	tpmFactory, err := tpmprovider.LinuxTpmFactoryProvider{}.NewTpmFactory()
	if err != nil {
		return errors.Wrap(err, "main:fetchEndorsementCert() Could not create tpm factory")
	}

	ekCertBytes, err := util.GetEndorsementKeyCertificateBytes(assetTagSecret, tpmFactory)

	if err != nil {
		log.WithError(err).Error("main:fetchEndorsementCert() Error while getting endorsement certificate in bytes from tpm")
		return errors.New("Error while getting endorsement certificate in bytes from tpm")
	}
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: ekCertBytes}); err != nil {
		log.WithError(err).Error("main:fetchEndorsementCert() Could not pem encode cert")
		return errors.New("Could not pem encode cert")
	}
	ekCerts, err := x509.ParseCertificates(ekCertBytes)
	if err != nil {
		log.WithError(err).Error("main:fetchEndorsementCert() Error while parsing endorsement certificate in bytes into x509 certificate")
		return errors.New("Error while parsing endorsement certificate in bytes into x509 certificate")
	}

	for _, ekCert := range ekCerts {
		fmt.Printf("Issuer: %s\n", ekCert.Issuer.CommonName)
		buf := new(bytes.Buffer)
		if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: ekCert.Raw}); err != nil {
			log.WithError(err).Error("main:fetchEndorsementCert() Could not pem encode cert")
			return errors.New("Could not pem encode cert")
		}
		base64EncodedCert := base64.StdEncoding.EncodeToString(buf.Bytes())
		fmt.Printf("TPM Endorsment Certificate Base64 Encoded: %s\n", base64EncodedCert)
	}
	return nil
}

func sendAsyncReportRequest(cfg *config.TrustAgentConfiguration) error {
	log.Trace("main:sendAsyncReportRequest() Entering")
	defer log.Trace("main:sendAsyncReportRequest() Leaving")

	var vsClientFactory hvsclient.HVSClientFactory
	vsClientFactory, err := hvsclient.NewVSClientFactory(cfg.HVS.Url, cfg.ApiToken,
		constants.TrustedCaCertsDir)
	if err != nil {
		// TA is not returning an error, since a user has to intervene to fix the issue, TA retrying infinitely would not be ideal in this case
		log.WithError(err).Error("Could not initiate hvs reports client")
		return nil
	}
	hostsClient, err := vsClientFactory.HostsClient()
	if err != nil {
		log.WithError(err).Error("Could not get the hvs hosts client")
		return nil
	}

	pInfo, err := util.ReadHostInfo(constants.PlatformInfoFilePath)
	if err != nil {
		// TA is not returning an error, since a user has to intervene to fix the issue, TA retrying infinitely would not be ideal in this case
		log.WithError(err).Errorf("Could not get host hardware uuid from %s file", constants.PlatformInfoFilePath)
		return nil
	}
	hostFilterCriteria := &hvs.HostFilterCriteria{HostHardwareId: uuid.MustParse(pInfo.HardwareUUID)}
	hostCollection, err := hostsClient.SearchHosts(hostFilterCriteria)
	if err != nil && strings.Contains(err.Error(), strconv.Itoa(http.StatusUnauthorized)) {
		log.WithError(err).Error("Could not get host details from HVS. Token expired, please update the token and restart TA")
		return nil
	} else if err != nil {
		log.WithError(err).Error("Could not get host details from HVS. TA will retry in few minutes")
		return err
	}
	if len(hostCollection.Hosts) > 0 {
		reportsClient, err := vsClientFactory.ReportsClient()
		if err != nil {
			// TA is not returning an error, since a user has to intervene to fix the issue, TA retrying infinitely would not be ideal in this case
			log.WithError(err).Error("Could not create hvs reports client")
			return nil
		}
		reportsCreateReq := hvs.ReportCreateRequest{HardwareUUID: uuid.MustParse(pInfo.HardwareUUID)}
		err, rsp := reportsClient.CreateReportAsync(reportsCreateReq)
		if rsp != nil && rsp.StatusCode == http.StatusUnauthorized {
			log.WithError(err).Error("Could not request for a new host attestation from HVS. Token expired, please update the token and restart TA")
			return nil
		} else if err != nil {
			log.WithError(err).Error("Could not request for a new host attestation from HVS. TA will retry in few minutes")
			return err
		}
		log.Debug("Successfully requested HVS to create a new trust report")
	}
	return nil
}

func asyncReportCreateRetry(cfg *config.TrustAgentConfiguration) {
	log.Trace("main:asyncReportCreateRetry() Entering")
	defer log.Trace("main:asyncReportCreateRetry() Leaving")

	ticker := time.NewTicker(constants.DefaultAsyncReportRetryInterval * time.Minute)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				err := sendAsyncReportRequest(cfg)
				if err == nil {
					close(quit)
				}
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}
