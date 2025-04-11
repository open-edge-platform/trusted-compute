/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package hosttrust

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hostfetcher "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/services/host-fetcher"
	mocks2 "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/mocks"
	libVerifier "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/verifier"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	qs             domain.QueueStore
	hs             *mocks.MockHostStore
	fs             *mocks.MockFlavorStore
	fgs            *mocks.MockFlavorgroupStore
	hss            *mocks.MockHostStatusStore
	cfg            domain.HostDataFetcherConfig
	ht             domain.HostTrustManager
	f              domain.HostDataFetcher
	hcs            domain.HostCredentialStore
	v              domain.HostTrustVerifier
	fIds           []uuid.UUID
	service        *Service
	hwUuid, hostId uuid.UUID
	hostManifest   hvs.HostManifest
)

func SetupManagerTests() {
	qs = mocks.NewQueueStore()
	hs = mocks.NewMockHostStore()
	fs = mocks.NewMockFlavorStore()
	fgs = mocks.NewFakeFlavorgroupStore()
	hss = mocks.NewMockHostStatusStore()
	hcs = mocks.NewMockHostCredentialStore()

	hwUuid = uuid.MustParse("0005AE6E-36D6-E711-906E-001560A04062")
	hostId = uuid.MustParse("204466f6-8611-4e03-934d-832172a41917")
	_, _ = hs.Create(&hvs.Host{
		HostName:         "hostname",
		Description:      "Host at test.domain.com",
		ConnectionString: "https://ta.ip.com:1443",
		HardwareUuid:     &hwUuid,
		Id:               hostId,
	})

	flavorCache, _ := lru.New(5)

	cfg = domain.HostDataFetcherConfig{
		HostConnectorProvider: mocks2.MockHostConnectorFactory{},
		HostConnectionConfig: domain.HostConnectionConfig{
			HCStore:         hcs,
			ServiceUsername: "serviceUsername",
			ServicePassword: "servicePassword",
		},
		RetryTimeMinutes: 7,
		HostStatusStore:  hss,
		HostStore:        hs,
		FlavorGroupStore: fgs,
		FlavorStore:      fs,
		HostTrustCache:   flavorCache,
	}

	_, f, _ = hostfetcher.NewService(cfg, 5)

	var fgIds []uuid.UUID
	//Add flavorgroup hvs_flavorgroup_test1 having flavor types platform, os and software to host
	fgIds = append(fgIds, uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"))
	//Add flavorgroup hvs_flavorgroup_test2 having flavor types host_unique to host
	fgIds = append(fgIds, uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"))
	hs.AddFlavorgroups(hostId, fgIds)

	flavorStore := mocks.NewFakeFlavorStoreWithAllFlavors("../../../lib/verifier/test_data/intel20/signed_flavors.json")
	flavorgroupStore := mocks.NewFakeFlavorgroupStore()
	flavorgroupStore.HostFlavorgroupStore = hs.HostFlavorgroupStore

	//platform flavor
	fIds = append(fIds, uuid.MustParse("b12eadd7-02da-4c9b-aed2-2252afa0260d"))
	// os flavor
	fIds = append(fIds, uuid.MustParse("49705d53-a75e-414e-998e-049cbb2a0ee6"))
	// software flavor
	fIds = append(fIds, uuid.MustParse("7f0683c1-a038-4ed4-8b29-286410f2e753"))
	// flavor group with software and platform
	flavorgroupStore.AddFlavors(uuid.MustParse("ee37c360-7eae-4250-a677-6ee12adce8e2"), fIds)

	fIds = make([]uuid.UUID, 1)
	// host_unique flavor
	fIds = append(fIds, uuid.MustParse("9a314548-5b36-479f-8158-463593e87193"))
	//Add host_unique flavor to host_unique flavorgroup
	flavorgroupStore.AddFlavors(uuid.MustParse("e57e5ea0-d465-461e-882d-1600090caa0d"), fIds)
	flavorStore.FlavorgroupStore = flavorgroupStore.FlavorgroupStore
	flavorStore.FlavorFlavorGroupStore = flavorgroupStore.FlavorgroupFlavorStore

	verifierCertificates := createVerifierCertificates(
		"../../../lib/verifier/test_data/intel20/PrivacyCA.pem",
		"../../../lib/verifier/test_data/intel20/flavor-signer.crt.pem",
		"../../../lib/verifier/test_data/intel20/cms-ca-cert.pem",
		"../../../lib/verifier/test_data/intel20/tag-cacerts.pem")

	flvrVerifier, _ := libVerifier.NewVerifier(*verifierCertificates)
	htvTrustCache, _ := lru.New(5)

	htv := domain.HostTrustVerifierConfig{
		FlavorStore:                     flavorStore,
		FlavorGroupStore:                flavorgroupStore,
		HostStore:                       hs,
		ReportStore:                     mocks.NewEmptyMockReportStore(),
		FlavorVerifier:                  flvrVerifier,
		SamlIssuerConfig:                *getIssuer(),
		SkipFlavorSignatureVerification: true,
		HostTrustCache:                  htvTrustCache,
	}
	v = NewVerifier(htv)

	service, ht, _ = NewService(domain.HostTrustMgrConfig{
		PersistStore:      qs,
		HostStore:         hs,
		HostStatusStore:   hss,
		HostFetcher:       f,
		Verifiers:         5,
		HostTrustVerifier: v,
	})

	manifestJSON, _ := ioutil.ReadFile("../../../lib/verifier/test_data/intel20/host_manifest.json")
	json.Unmarshal(manifestJSON, &hostManifest)
}

func TestHostTrustManagerNewService(t *testing.T) {
	SetupManagerTests()

	hwUuid, err := uuid.NewRandom()
	assert.NoError(t, err)

	newHost, err := hs.Create(&hvs.Host{
		HostName:         "test.domain.com",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     &hwUuid,
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id, nil)
	fmt.Println(hrec)
	assert.NoError(t, err)

	err = ht.VerifyHostsAsync([]uuid.UUID{newHost.Id}, true, false)
	assert.NoError(t, err)
	time.Sleep(5 * time.Second)

	qrecs, err := qs.Search(&models.QueueFilterCriteria{})
	assert.NoError(t, err)
	for _, qrec := range qrecs {
		fmt.Println(*qrec)
	}
}

func TestVerifier_Verify_UntrustedHost(t *testing.T) {
	SetupManagerTests()
	report, err := v.Verify(hostId, &hostManifest, false, false)
	assert.NoError(t, err)
	fmt.Println(report.TrustReport.Trusted)
	assert.Equal(t, report.TrustReport.Trusted, false)
	fmt.Println(report.Saml)
	assert.NoError(t, err)
}

func TestHostTrustManagerShutdown(t *testing.T) {
	SetupManagerTests()
	hwUuid, err := uuid.NewRandom()
	assert.NoError(t, err)

	newHost, err := hs.Create(&hvs.Host{
		HostName:         "test.domain.com",
		Description:      "Host at test.domain.com",
		ConnectionString: "intel://test.domain.com/ta",
		HardwareUuid:     &hwUuid,
	})
	assert.NoError(t, err)
	hrec, err := hs.Retrieve(newHost.Id, nil)
	fmt.Println(hrec)
	assert.NoError(t, err)

	// load up a large number of hosts and check if the shutdown is processed
	// when the signal is received
	assert.NoError(t, ht.VerifyHostsAsync([]uuid.UUID{hwUuid}, true, false), "Async calls pre-shutdown should not return error")

	// call shutdown signal
	err = service.Shutdown()
	assert.NoError(t, err)

	// check if the service has been shutdown
	assert.Error(t, ht.VerifyHostsAsync([]uuid.UUID{hwUuid}, true, false), "Service post shutdown should return error")
}

func TestManager_VerifyHostSyncWithHostDataFetch(t *testing.T) {
	SetupManagerTests()

	_, err := service.VerifyHost(hostId, true, false)
	assert.NoError(t, err, "VerifyHost should not return an error when HostData is fetched")
}

func TestManager_VerifyHostSyncWithoutHostDataFetch(t *testing.T) {
	SetupManagerTests()
	_, err := service.VerifyHost(hostId, false, false)
	assert.Error(t, err, "VerifyHost should error out when the Host manifest is not present in HostStatus")
}

func TestManager_VerifyHostAsync(t *testing.T) {
	SetupManagerTests()
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, true, false),
		"VerifyHostAsync should not return an error")
	strRec := &models.Queue{Action: "flavor-verify",
		Params: map[string]interface{}{"host_id": "7060b9da-08c6-4cbc-9ac1-446b8df6f123", "fetch_host_data": false, "prefer_hash_match": true},
		State:  models.QueueStatePending,
	}
	strRec, err := service.prstStor.Create(strRec)
	if err != nil {
		log.Error("Error in creating hosts in persistent store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	service.hosts.Store(uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f123"), &verifyTrustJob{ctx, cancel, nil, strRec.Id,
		false, true})
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f123")}, true, false),
		"VerifyHostAsync should not return an error")
	service.hosts.Store(uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f123"), &verifyTrustJob{ctx, cancel, nil, uuid.Nil,
		false, true})
	assert.Error(t, service.VerifyHostsAsync([]uuid.UUID{uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f123")}, true, false),
		"VerifyHostAsync should not return an error")

	//Delete dangling entries
	strRec = &models.Queue{Action: "flavor-verify",
		Params: map[string]interface{}{"host_id": "7060b9da-08c6-4cbc-9ac1-446b8df6f124", "fetch_host_data": false, "prefer_hash_match": true},
		State:  models.QueueStatePending,
	}
	strRec, err = service.prstStor.Create(strRec)
	if err != nil {
		log.Error("Error in creating hosts in persistent store")
	}
	// Deletes dangling entry
	service.deleteEntry(uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f124"))
	// Deletes non existent dangling entry
	service.deleteEntry(uuid.MustParse("7060b9da-08c6-4cbc-9ac1-446b8df6f125"))
}

func TestManager_VerifyQueueLogic(t *testing.T) {
	SetupManagerTests()

	for i := 0; i < 100; i++ {
		go assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, true, false),
			"VerifyHostAsync should not return an error")
		go assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, false, false),
			"VerifyHostAsync should not return an error")
		assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, true, true),
			"VerifyHostAsync should not return an error")
		assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{hostId}, false, true),
			"VerifyHostAsync should not return an error")
	}

	// queue length should not be greater than 0
	assert.NoError(t, service.ProcessQueue(), "Process Queue should be empty")
}

func TestManager_VerifyNonExistentHost(t *testing.T) {
	SetupManagerTests()
	hostCred := &models.HostCredential{
		HostName:   "hostname",
		Credential: "https://ta.ip.com:1443",
		CreatedTs:  time.Now(),
	}
	newUuid, err := uuid.NewRandom()
	assert.NoError(t, err)
	hostCred.Id = newUuid
	newUuid, err = uuid.NewRandom()
	assert.NoError(t, err)
	hostCred.HostId = newUuid
	// add entries to HostCredentialStore
	hcs.Create(hostCred)

	newId, err := uuid.NewRandom()
	assert.NoError(t, err)
	_, err = service.VerifyHost(newId, true, false)
	assert.Error(t, err, "VerifyHost should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	_, err = service.VerifyHost(newId, false, false)
	assert.Error(t, err, "VerifyHost should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{newId}, true, false), "VerifyHostVerifyHostsAsync should error out when the Host does not exist")
	newId, err = uuid.NewRandom()
	assert.NoError(t, err)
	assert.NoError(t, service.VerifyHostsAsync([]uuid.UUID{newId}, false, false), "VerifyHostsAsync should error out when the Host does not exist")
}

func Test_shouldCancelPrevJob(t *testing.T) {
	type args struct {
		newJobNeedFreshHostData bool
		prevJobNeededFreshData  bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: " Previous job needs fresh data and new job doesn't need fresh data",
			args: args{
				newJobNeedFreshHostData: false,
				prevJobNeededFreshData:  true,
			},
			want: false,
		},
		{
			name: " Previous job does not need fresh data and new job doesn't need fresh data",
			args: args{
				newJobNeedFreshHostData: false,
				prevJobNeededFreshData:  false,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldCancelPrevJob(tt.args.newJobNeedFreshHostData, tt.args.prevJobNeededFreshData); got != tt.want {
				t.Errorf("shouldCancelPrevJob() = %v, want %v", got, tt.want)
			}
		})
	}
}
