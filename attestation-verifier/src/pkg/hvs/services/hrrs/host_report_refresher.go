/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hrrs

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"

	"github.com/pkg/errors"
)

// HostReportRefresher runs in the background and periodically queries HVS'
// reports to see if they have been expired.  If so, they are passed to
// the HostTrustManager queue to be updated.
type HostReportRefresher interface {
	Run() error
	Stop() error
}

var (
	firstFromTime, _ = time.Parse(time.RFC3339, "1970-01-01T00:00:00Z") // i.e. epoch
	defaultLog       = commLog.GetDefaultLogger()
)

func NewHostReportRefresher(cfg HRRSConfig, reportStore domain.ReportStore, hostTrustManager domain.HostTrustManager) (HostReportRefresher, error) {

	return &hostReportRefresherImpl{
		reportStore:      reportStore,
		hostTrustManager: hostTrustManager,
		cfg:              cfg,
		fromTime:         firstFromTime,
	}, nil
}

type hostReportRefresherImpl struct {
	reportStore      domain.ReportStore
	hostTrustManager domain.HostTrustManager
	cfg              HRRSConfig
	ctx              context.Context
	fromTime         time.Time
}

func (refresher *hostReportRefresherImpl) Run() error {

	defaultLog.Infof("HRRS is starting with refresh period '%s'", refresher.cfg.RefreshPeriod)

	if refresher.cfg.RefreshPeriod == 0 {
		defaultLog.Info("The HRRS refresh period is zero.  HRRS will now exit")
		return nil
	}

	refresher.ctx = context.Background()

	go func() {
		defer func() {
			if err := recover(); err != nil {
				defaultLog.Errorf("Panic occurred: %+v", err)
				defaultLog.Error(string(debug.Stack()))
			}
		}()
		for {
			err := refresher.refreshReports()
			if err != nil {
				// log any errors, but do not stop trying to refresh reports
				defaultLog.Errorf("HRRS encountered an error while refreshing reports...\n%+v\n", err)
			}

			select {
			case <-time.After(refresher.cfg.RefreshPeriod):
				// continue with the loop and refresh reports again
			case <-refresher.ctx.Done():
				defaultLog.Info("The HRRS has been stopped and will now exit")
			}
		}
	}()

	return nil
}

func (refresher *hostReportRefresherImpl) Stop() error {
	if refresher.ctx != nil {
		refresher.ctx.Done()
	} else {
		defaultLog.Debug("The HRRS is not running")
	}

	return nil
}

// Uses an 'expiration time window' to find expired reports.
//
// - On the first pass, the window is from the epoch to the next 'refresh period' from now.
//   This will attempt to queue all hosts that have an expired report.
// - On subsequent calls, the window wll be from the last time this function was called,
//   to the next 'refresh period'.
//
// The intent of this logic is to avoid adding duplicate hosts to the
// HostTrustManage queue.
func (refresher *hostReportRefresherImpl) refreshReports() error {

	toTime := time.Now().UTC().Add(refresher.cfg.RefreshPeriod)
	defaultLog.Debugf("HRRS is refreshing hosts that have expired reports between %s and %s", refresher.fromTime, toTime)

	hostIDs, err := refresher.reportStore.FindHostIdsFromExpiredReports(refresher.fromTime, toTime)

	if err != nil {
		return errors.Wrap(err, "An error occurred while HRRS searched for host ids")
	}

	defaultLog.Debugf("HRRS found %d hosts to refresh", len(hostIDs))

	if len(hostIDs) > 0 {
		err = refresher.hostTrustManager.VerifyHostsAsync(hostIDs, true, true)
		if err != nil {
			return errors.Wrap(err, "HRRS encountered an error calling the host trust manager")
		}
	}

	defaultLog.Infof("HRRS queued %d hosts from reports that were expiring between %s and %s", len(hostIDs), refresher.fromTime, toTime)
	refresher.fromTime = toTime

	return nil
}
