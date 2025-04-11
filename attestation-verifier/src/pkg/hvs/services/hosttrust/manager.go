/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"context"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/google/uuid"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models/taskstage"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/chnlworkq"
	commLog "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/log"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	"github.com/pkg/errors"
	"golang.org/x/sync/syncmap"
)

var defaultLog = commLog.GetDefaultLogger()

type verifyTrustJob struct {
	ctx             context.Context
	cancelFn        context.CancelFunc
	host            *hvs.Host
	storPersistId   uuid.UUID
	getNewHostData  bool
	preferHashMatch bool
}

type newHostFetch struct {
	ctx             context.Context
	hostId          uuid.UUID
	data            *hvs.HostManifest
	preferHashMatch bool
}

type Service struct {
	// channel that hold requests that came back from host data fetch
	hfRqstChan chan interface{}
	// channel that hold queued flavor verify that came back from host data fetch.
	// The workers processing this do not need to get the data from the store.
	// It is already in the channel
	hfWorkChan chan interface{}
	// request channel is used to route requests into internal queue
	rqstChan chan interface{}
	// work items (their id) is pulled out of a queue and fed to the workers
	workChan chan interface{}
	// map that holds all the hosts that needs trust verification.
	hosts syncmap.Map
	// syncMtx is used to synchronize shared access to the Queue store and the work map across worker threads
	syncMtx sync.Mutex
	//
	prstStor        domain.QueueStore
	hdFetcher       domain.HostDataFetcher
	hostStore       domain.HostStore
	verifier        domain.HostTrustVerifier
	hostStatusStore domain.HostStatusStore
	// waitgroup used to wait for workers to finish up when signal for shutdown comes in
	wg          sync.WaitGroup
	quit        chan struct{}
	serviceDone bool
}

func NewService(cfg domain.HostTrustMgrConfig) (*Service, domain.HostTrustManager, error) {
	defaultLog.Trace("hosttrust/manager:NewService() Entering")
	defer defaultLog.Trace("hosttrust/manager:NewService() Leaving")

	svc := &Service{prstStor: cfg.PersistStore,
		hdFetcher:       cfg.HostFetcher,
		hostStore:       cfg.HostStore,
		verifier:        cfg.HostTrustVerifier,
		hostStatusStore: cfg.HostStatusStore,
		quit:            make(chan struct{}),
		hosts:           syncmap.Map{},
	}
	var err error
	nw := cfg.Verifiers
	if svc.rqstChan, svc.workChan, err = chnlworkq.New(nw, nw, nil, nil, svc.quit, &svc.wg); err != nil {
		return nil, nil, errors.New("hosttrust:NewService:Error starting work queue")
	}
	if svc.hfRqstChan, svc.hfWorkChan, err = chnlworkq.New(nw, nw, nil, nil, svc.quit, &svc.wg); err != nil {
		return nil, nil, errors.New("hosttrust:NewService:Error starting work queue")
	}

	// start go routines
	svc.startWorkers(cfg.Verifiers)
	return svc, svc, nil
}

// Function to Shutdown service. Will wait for pending host data fetch jobs to complete
// Will not process any further requests. Calling interface Async methods will result in error
func (svc *Service) Shutdown() error {
	defaultLog.Trace("hosttrust/manager:Shutdown() Entering")
	defer defaultLog.Trace("hosttrust/manager:Shutdown() Leaving")

	svc.serviceDone = true
	close(svc.quit)
	svc.wg.Wait()

	return nil
}

func (svc *Service) startWorkers(workers int) {
	defaultLog.Trace("hosttrust/manager:startWorkers() Entering")
	defer defaultLog.Trace("hosttrust/manager:startWorkers() Leaving")

	// start worker go routines
	for i := 0; i < workers; i++ {
		svc.wg.Add(1)
		go svc.doWork()
	}
}

func (svc *Service) VerifyHost(hostId uuid.UUID, fetchHostData bool, preferHashMatch bool) (*models.HVSReport, error) {
	var hostData *hvs.HostManifest

	if fetchHostData {
		var host *hvs.Host
		host, err := svc.hostStore.Retrieve(hostId, nil)
		if err != nil {
			return nil, errors.Wrap(err, "could not retrieve host id "+hostId.String())
		}

		hostData, err = svc.hdFetcher.Retrieve(hvs.Host{
			Id:               host.Id,
			ConnectionString: host.ConnectionString})
	} else {
		hostStatusCollection, err := svc.hostStatusStore.Search(&models.HostStatusFilterCriteria{
			HostId:        hostId,
			LatestPerHost: true,
		})
		if err != nil || len(hostStatusCollection) == 0 || hostStatusCollection[0].HostStatusInformation.HostState != hvs.HostStateConnected {
			return nil, errors.New("could not retrieve host manifest for host id " + hostId.String())
		}

		hostData = &hostStatusCollection[0].HostManifest
	}
	newData := fetchHostData
	return svc.verifier.Verify(hostId, hostData, newData, preferHashMatch)
}

func (svc *Service) ProcessQueue() error {
	defaultLog.Trace("hosttrust/manager:ProcessQueue() Entering")
	defer defaultLog.Trace("hosttrust/manager:ProcessQueue() Leaving")

	records, err := svc.prstStor.Search(nil)
	if err != nil {
		return errors.Wrap(err, "An error occurred while searching for records in queue")
	}

	verifyWithFetchDataHostIds := map[uuid.UUID]bool{}
	verifyHostIds := map[uuid.UUID]bool{}
	if len(records) > 0 {
		for _, queue := range records {
			if queue.Params != nil {
				var hostId uuid.UUID
				fetchHostData := false
				preferHashMatch := false
				for key, value := range queue.Params {
					if key == "host_id" {
						if _, ok := value.(string); ok {
							hostId, err = uuid.Parse(value.(string))
							if err != nil {
								return errors.Wrap(err, "hosttrust/manager:ProcessQueue() - parsing hostid failed")
							}
						} else {
							hostId = value.(uuid.UUID)
						}
					}
					if key == "fetch_host_data" {
						fetchHostData = value.(bool)
					}
					if key == "prefer_hash_match" {
						preferHashMatch = value.(bool)
					}
				}
				if fetchHostData {
					verifyWithFetchDataHostIds[hostId] = preferHashMatch
				} else {
					verifyHostIds[hostId] = true
				}
				ctx, cancel := context.WithCancel(context.Background())

				// the host field is not filled at this stage since it requires a trip to the host store
				svc.hosts.Store(hostId, &verifyTrustJob{ctx, cancel, nil, queue.Id,
					fetchHostData, preferHashMatch})
			}
		}
	}

	if len(verifyWithFetchDataHostIds) > 0 {
		svc.wg.Add(1)
		go svc.submitHostDataFetch(verifyWithFetchDataHostIds)
	}
	if len(verifyHostIds) > 0 {
		go svc.queueFlavorVerify(verifyHostIds)
	}
	return nil
}

func (svc *Service) VerifyHostsAsync(hostIds []uuid.UUID, fetchHostData, preferHashMatch bool) error {
	defaultLog.Trace("hosttrust/manager:VerifyHostsAsync() Entering")
	defer defaultLog.Trace("hosttrust/manager:VerifyHostsAsync() Leaving")

	defaultLog.Debugf("hosttrust/manager:VerifyHostsAsync() VHAsync for %v", hostIds)

	svc.syncMtx.Lock()
	defer svc.syncMtx.Unlock()

	// check if the service has already been shutdown
	if svc.serviceDone {
		return errors.New("hosttrust/manager:VerifyHostsAsync() Service already shutdown")
	}

	adds := map[uuid.UUID]bool{}
	updates := map[uuid.UUID]bool{}

	// iterate through the hosts and check if there is an existing entry
	for _, hid := range hostIds {
		vt, found := svc.hosts.Load(hid)
		var vtj *verifyTrustJob
		if found {
			vtj = vt.(*verifyTrustJob)
			prevJobStage, _ := taskstage.FromContext(vtj.ctx)
			bothPreferHashMatch := preferHashMatch == vtj.preferHashMatch
			if isDuplicateJob(fetchHostData, vtj.getNewHostData, bothPreferHashMatch, prevJobStage) {
				defaultLog.Debugf("hosttrust/manager:VerifyHostsAsync() Skipping dupe FVS job hostFetch - %s - for host %v", strconv.FormatBool(fetchHostData), hid)
				continue
			}
			// cancel current job if it prefers hash match and old one does not as old might change host trust status
			if preferHashMatch && !vtj.preferHashMatch {
				defaultLog.Debugf("hosttrust/manager:VerifyHostsAsync() Old job does not prefer hash match %v. Skipping new job.", hid)
				continue
			} else if (!preferHashMatch && vtj.preferHashMatch) || shouldCancelPrevJob(fetchHostData, vtj.getNewHostData) {
				defaultLog.Debugf("hosttrust/manager:VerifyHostsAsync() New job does not prefer hash match %v. Updating host entry", hid)
				vtj.cancelFn()
				updates[hid] = preferHashMatch
			}
		} else {
			adds[hid] = preferHashMatch
			defaultLog.Debugf("hosttrust/manager:VerifyHostsAsync() Appends for %v", hid)
		}
	}
	if err := svc.persistToStore(adds, updates, fetchHostData, preferHashMatch); err != nil {
		defaultLog.Errorf("hosttrust/manager:VerifyHostsAsync() Error in persistToStore for %s - %s", hostIds[0].String(), err.Error())
		return errors.Wrap(err, "hosttrust/manager:VerifyHostsAsync() persistRequest - error in Persisting to Store")
	}

	// at this point, it is safe to return the async call as the records have been persisted.
	if fetchHostData {
		svc.wg.Add(1)
		go svc.submitHostDataFetch(adds)
	} else {
		go svc.queueFlavorVerify(adds, updates)
	}
	return nil
}

func (svc *Service) submitHostDataFetch(hostLists map[uuid.UUID]bool) {
	defaultLog.Trace("hosttrust/manager:submitHostDataFetch() Entering")
	defer defaultLog.Trace("hosttrust/manager:submitHostDataFetch() Leaving")

	defer svc.wg.Done()
	for hId, preferHashMatch := range hostLists {
		// since current store method only support searching one record at a time, use that.
		// TODO: update to bulk retrieve host records when store method supports it. In this case, iterate by
		// result from the host store.
		if host, err := svc.hostStore.Retrieve(hId, nil); err != nil {
			defaultLog.Info("hosttrust/manager:submitHostDataFetch() - error retrieving host data for id", hId)
			continue
		} else {
			vt, ok := svc.hosts.Load(hId)
			if !ok {
				defaultLog.Error("hosttrust/manager:submitHostDataFetch() - Unexpected error retrieving map entry for id:", hId)
				continue
			}
			vtj := vt.(*verifyTrustJob)
			vtj.host = host

			taskstage.StoreInContext(vtj.ctx, taskstage.GetHostDataQueued)

			if err := svc.hdFetcher.RetrieveAsync(vtj.ctx, *vtj.host, preferHashMatch, svc); err != nil {
				defaultLog.Error("hosttrust/manager:submitHostDataFetch() - error calling RetrieveAsync", hId)
			}
		}
	}
}

func (svc *Service) queueFlavorVerify(hostsLists ...map[uuid.UUID]bool) {
	defaultLog.Trace("hosttrust/manager:queueFlavorVerify() Entering")
	defer defaultLog.Trace("hosttrust/manager:queueFlavorVerify() Leaving")

	for _, hosts := range hostsLists {
		// unlike the submitHostDataFetch, this one needs to be processed one at a time.
		for hId := range hosts {
			// here the map already has the information that we need to start the job. The host data
			// is not available - but the worker thread should just retrieve it individually from the
			// go routine. So, all we have to do is submit requests
			svc.rqstChan <- hId
			// the go routine that manages the work queue will process the request. It only blocks till the
			// request is copied to the internal queue
		}
	}
}

func (svc *Service) persistToStore(additions, updates map[uuid.UUID]bool, fetchHostData, preferHashMatch bool) error {
	defaultLog.Trace("hosttrust/manager:persistToStore() Entering")
	defer defaultLog.Trace("hosttrust/manager:persistToStore() Leaving")

	defaultLog.Debugf("hosttrust/manager:persistToStore() Additions - %+v", additions)

	addToStore := func(hid uuid.UUID) error {
		strRec := &models.Queue{Action: "flavor-verify",
			Params: map[string]interface{}{"host_id": hid, "fetch_host_data": fetchHostData, "prefer_hash_match": preferHashMatch},
			State:  models.QueueStatePending,
		}
		var err error

		_, htvJobExists := svc.hosts.Load(hid)
		if htvJobExists {
			updates[hid] = true
		}
		// if record does not exist in map
		if !htvJobExists {
			defaultLog.Debugf("hosttrust/manager:persistToStore() Create for host %s ", hid.String())

			ctx, cancel := context.WithCancel(context.Background())
			if strRec, err = svc.prstStor.Create(strRec); err != nil {
				defaultLog.Errorf("hosttrust/manager:persistToStore() Queue store persist failed for host %s - %s", hid.String(), err.Error())
				cancel()
				return errors.Wrapf(err, "hosttrust/manager:persistToStore() - Could not create queue record for host %s", hid.String())
			}
			defaultLog.Debugf("hosttrust/manager:persistToStore() Creating FVQueue entry %v for host %s", strRec.Id, hid.String())

			// the host field is not filled at this stage since it requires a trip to the host store
			svc.hosts.Store(hid, &verifyTrustJob{ctx, cancel, nil, strRec.Id,
				fetchHostData, preferHashMatch})
		}
		return nil
	}

	for hid := range additions {
		if err := addToStore(hid); err != nil {
			return err
		}
	}

	updateToStore := func(hid uuid.UUID) error {
		strRec := &models.Queue{Action: "flavor-verify",
			Params: map[string]interface{}{"host_id": hid, "fetch_host_data": fetchHostData, "prefer_hash_match": preferHashMatch},
			State:  models.QueueStatePending,
		}

		defaultLog.Debugf("hosttrust/manager:updateToStore() Update for host %s ", hid.String())
		vt, htvJobExists := svc.hosts.Load(hid)
		var existingHTVJob *verifyTrustJob
		if htvJobExists {
			existingHTVJob = vt.(*verifyTrustJob)

			currRec, err := svc.prstStor.Retrieve(existingHTVJob.storPersistId)
			defaultLog.Debugf("hosttrust/manager:updateToStore() Existing Queue entry %v for host %v", currRec, hid)
			if err != nil {
				defaultLog.Errorf("hosttrust/manager:updateToStore() Failed to fetch existing queue store entryfor"+
					" host %s | %s", hid.String(), err.Error())
				return err
			}
			currRec.Params = strRec.Params
			defaultLog.Debugf("hosttrust/manager:updateToStore() Updating FVQueue entry %v for host %v",
				existingHTVJob.storPersistId, hid)
			if err = svc.prstStor.Update(currRec); err != nil {
				defaultLog.Errorf("hosttrust/manager:updateToStore() Queue store update failed for host %s - %s",
					hid.String(), err.Error())
				return err
			}

			// update work map
			ctx, cancel := context.WithCancel(context.Background())
			existingHTVJob.ctx = ctx
			existingHTVJob.cancelFn = cancel
			existingHTVJob.getNewHostData = fetchHostData
			existingHTVJob.preferHashMatch = preferHashMatch
			svc.hosts.Store(hid, existingHTVJob)
		}

		return nil
	}

	for hid := range updates {
		if err := updateToStore(hid); err != nil {
			return err
		}
	}

	return nil
}

// function that does the actual work. There are two separate channels that contains work.
// First one is the flavor verification work submitted that does not require new host data
// Second one is work that first requires new data from host.
// In the first case, the host data has to be retrieved from the store.
// second case, the host data is already available in the work channel - so there is no
// need to fetch from the store.
func (svc *Service) doWork() {
	defaultLog.Trace("hosttrust/manager:doWork() Entering")
	defer defaultLog.Trace("hosttrust/manager:doWork() Leaving")

	defer func() {
		if err := recover(); err != nil {
			defaultLog.Errorf("Panic occurred: %+v", err)
			defaultLog.Error(string(debug.Stack()))
		}
		svc.wg.Done()
	}()

	// receive id of queued work over the channel.
	// Fetch work context from the map.
	for {
		var hostId uuid.UUID
		var hostData *hvs.HostManifest
		newData := false
		preferHashMatch := false

		select {

		case <-svc.quit:
			// we have received a quit. Don't process anymore items - just return
			return

		case id := <-svc.workChan:
			if hId, ok := id.(uuid.UUID); !ok {
				defaultLog.Error("hosttrust/manager:doWork() expecting uuid from channel - but got different type")
				return
			} else {
				defaultLog.Debugf("hosttrust/manager:doWork() Processing queue entry for host %s", hId.String())

				hostStatusCollection, err := svc.hostStatusStore.Search(&models.HostStatusFilterCriteria{
					HostId:        hId,
					LatestPerHost: true,
				})

				if err != nil {
					defaultLog.Errorf("hosttrust/manager:doWork() - an error occurred retrieving host data from store for host - %s  | error: %s ", hId.String(), err.Error())
					return
				}

				if hostStatusCollection == nil || len(hostStatusCollection) == 0 {
					defaultLog.Errorf("hosttrust/manager:doWork() - a report refresh was requested for host %s, but it does not exists", hId.String())
					return
				}

				if hostStatusCollection[0].HostStatusInformation.HostState != hvs.HostStateConnected {
					defaultLog.Debugf("hosttrust/manager:doWork() - the host is not connected - %s", hId.String())
					return
				}

				hostId = hId
				hostData = &hostStatusCollection[0].HostManifest
			}

		case data := <-svc.hfWorkChan:
			if hData, ok := data.(newHostFetch); !ok {
				defaultLog.Error("hosttrust/manager:doWork() expecting newHostFetch type from channel - but got different one")
				return
			} else {
				hostId = hData.hostId
				hostData = hData.data
				preferHashMatch = hData.preferHashMatch
				newData = true
				defaultLog.Debugf("hosttrust/manager:doWork() - inHfWorkChan for host - %s", hostId.String())
			}

		}
		svc.verifyHostData(hostId, hostData, newData, preferHashMatch)
	}
}

// This function kicks of the verification process given a manifest
func (svc *Service) verifyHostData(hostId uuid.UUID, data *hvs.HostManifest, newData bool, preferHashMatch bool) {
	defaultLog.Trace("hosttrust/manager:verifyHostData() Entering")
	defer defaultLog.Trace("hosttrust/manager:verifyHostData() Leaving")

	defaultLog.Debugf("hosttrust/manager:verifyHostData() host - %s", hostId.String())

	//check if the job has not already been cancelled
	vt, jobFound := svc.hosts.Load(hostId)
	// if job is not found in work map nothing more to do here
	if !jobFound {
		defaultLog.Info("Host ", hostId, " removed from hosts work map")
		return
	}
	vtj := vt.(*verifyTrustJob)
	select {
	// remove the requests that have already been cancelled.
	case <-vtj.ctx.Done():
		defaultLog.Debug("Host Flavor verification is cancelled for host id", hostId, "...continuing to next one")
		return
	default:
		taskstage.StoreInContext(vtj.ctx, taskstage.FlavorVerifyStarted)
	}

	_, err := svc.verifier.Verify(hostId, data, newData, preferHashMatch)
	if err != nil {
		defaultLog.WithError(err).Errorf("hosttrust/manager:verifyHostData() Error while verification: %s", hostId.String())
	}
	// verify is completed - delete the entry
	svc.deleteEntry(hostId)
}

// This function is the implementation of the HostDataReceiver interface method. Just create a new request
// to process the newly obtained data and it will be submitted to the verification queue
func (svc *Service) ProcessHostData(ctx context.Context, host hvs.Host, data *hvs.HostManifest, preferHashMatch bool, err error) error {
	defaultLog.Trace("hosttrust/manager:ProcessHostData() Entering")
	defer defaultLog.Trace("hosttrust/manager:ProcessHostData() Leaving")

	select {
	case <-ctx.Done():
		return nil
	default:
	}
	// if there is an error - delete the entry
	if err != nil {
		defaultLog.WithError(err).Errorf("hosttrust/manager:ProcessHostData() Error in host data fetch for host %v", host.Id)
		svc.deleteEntry(host.Id)
	}

	// queue the new data to be processed by one of the worker threads by adding this to the queue
	taskstage.StoreInContext(ctx, taskstage.FlavorVerifyQueued)
	svc.hfRqstChan <- newHostFetch{
		ctx:             ctx,
		hostId:          host.Id,
		data:            data,
		preferHashMatch: preferHashMatch,
	}
	return nil
}

// isDuplicateJob determines if the new incoming job is a dupe of currently running job
func isDuplicateJob(newJobNeedFreshHostData, prevJobNeededFreshData, bothPreferHashMatch bool, prevJobStage taskstage.Stage) bool {
	defaultLog.Trace("hosttrust/manager:isDuplicateJob() Entering")
	defer defaultLog.Trace("hosttrust/manager:isDuplicateJob() Leaving")

	if (prevJobStage < taskstage.FlavorVerifyStarted && bothPreferHashMatch &&
		prevJobNeededFreshData == newJobNeedFreshHostData == false) ||
		(prevJobStage < taskstage.GetHostDataStarted && bothPreferHashMatch &&
			prevJobNeededFreshData == newJobNeedFreshHostData == true) {
		return true
	}
	return false
}

// shouldCancelPrevJob determines if the previous job can be cancelled out
func shouldCancelPrevJob(newJobNeedFreshHostData, prevJobNeededFreshData bool) bool {
	defaultLog.Trace("hosttrust/manager:shouldCancelPrevJob() Entering")
	defer defaultLog.Trace("hosttrust/manager:shouldCancelPrevJob() Leaving")

	// if the old job needs data and the new job doesn't then DON'T cancel old job
	if prevJobNeededFreshData && !newJobNeedFreshHostData {
		return false
	}

	// in all other cases
	return true
}

func (svc *Service) deleteEntry(hostId uuid.UUID) {
	defaultLog.Trace("hosttrust/manager:deleteEntry() Entering")
	defer defaultLog.Trace("hosttrust/manager:deleteEntry() Leaving")

	svc.syncMtx.Lock()
	defer svc.syncMtx.Unlock()

	vt, exists := svc.hosts.Load(hostId)
	if exists {
		strRec := vt.(*verifyTrustJob)
		strRec.ctx.Done()
		defaultLog.Debugf("Deleting queue entry %v for host %v", strRec.storPersistId, hostId)
		svc.hosts.Delete(hostId)
		if err := svc.prstStor.Delete(strRec.storPersistId); err != nil {
			defaultLog.Errorf("could not delete from persistent queue store err for entry id %v | "+
				"host id %v - %v", strRec.storPersistId, hostId, err)
		}
	} else {
		// delete all dangling entries in the queue store
		// look up entries
		danglingEntries, err := svc.prstStor.Search(&models.QueueFilterCriteria{
			ParamKey:   "host_id",
			ParamValue: hostId.String(),
		})
		if err != nil {
			defaultLog.Errorf("failure search entries from persistent queue store for host %v - %v",
				hostId, err)
			return
		}

		for _, dangEntry := range danglingEntries {
			if deleteErr := svc.prstStor.Delete(dangEntry.Id); deleteErr != nil {
				defaultLog.Errorf("could not delete from persistent queue store err for entry %v | "+
					"host %v - %v", dangEntry.Id, hostId, deleteErr)
			} else {
				defaultLog.Debugf("deleted dangling entry from persistent queue store %v host - %v",
					dangEntry.Id, hostId)
			}
		}
	}
}
