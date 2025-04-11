/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package rules

import (
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/util"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
)

const (
	PCR_VALID_256   = "00000000000000000000"
	PCR_INVALID_256 = "11111111111111111111"
)

var (
	validAssetTagBytes    = []byte{'b', 'e', 'e', 'f'}
	invalidAssetTagBytes  = []byte{'d', 'e', 'a', 'd'}
	validAssetTagString   = "YmVlZg=="
	invalidAssetTagString = "ZGVhZA=="
	assetTags             = []hvs.TagKvAttribute{
		{Key: "Country", Value: "US"},
	}
)

var (
	zeros           = "00000000000000000000000000000000"
	ones            = "11111111111111111111111111111111"
	testExpectedPcr = hvs.FlavorPcrs{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},

		Measurement: PCR_VALID_256,
	}

	testExpectedPcrEventLogEntry = hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},

		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},
		},
	}
)

var (
	testHostManifestPcrEventLogEntry = hvs.TpmEventLog{
		Pcr: hvs.Pcr{
			Index: 0,
			Bank:  "SHA256",
		},

		TpmEvent: []hvs.EventLog{
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: zeros,
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: ones,
			},

			// these should be stripped by the rule...
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "a",
				Tags:        []string{"commandLine."},
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "b",
				Tags:        []string{"LCP_CONTROL_HASH"},
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "c",
				Tags:        []string{"initrd"},
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "d",
				Tags:        []string{"vmlinuz"},
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "e",
				Tags:        []string{"componentName.imgdb.tgz"},
			},
			{
				TypeName:    util.EVENT_LOG_DIGEST_SHA256,
				Measurement: "f",
				Tags:        []string{"componentName.onetime.tgz"},
			},
		},
	}
)

var (
	testMeasurementXml = `<?xml version="1.0" encoding="UTF-8"?>
	 <Measurement xmlns="lib:wml:measurements:1.0" Label="ISecL_Default_Application_Flavor_v2.0_TPM2.0" Uuid="5aed8104-f68b-40a1-b8f1-b646ecf33b40" DigestAlg="SHA384">
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/bin">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/dracut_files">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/initrd_hooks">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/lib">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/mkinitrd_files">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir>
		<File Path="/opt/tbootxm/bin/tpmextend">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File>
		<File Path="/opt/tbootxm/bin/measure">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File>
		<File Path="/opt/tbootxm/bin/configure_host.sh">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File>
		<File Path="/opt/tbootxm/bin/generate_initrd.sh">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File>
		<File Path="/opt/tbootxm/bin/measure_host">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File>
		<File Path="/opt/tbootxm/bin/tboot-xm-uninstall.sh">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File>
		<File Path="/opt/tbootxm/bin/functions.sh">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File>
		<File Path="/opt/tbootxm/dracut_files/check">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File>
		<File Path="/opt/tbootxm/dracut_files/install">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File>
		<File Path="/opt/tbootxm/dracut_files/module-setup.sh">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File>
		<File Path="/opt/tbootxm/lib/libwml.so">4b33910d5d03045275c2e8593f8bebefc2d4689c575a198a516121b25f44269107fb5075d1b5d9b35cf0b1da56b9e1e9</File>
		<File Path="/opt/tbootxm/lib/create_menuentry.pl">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File>
		<File Path="/opt/tbootxm/lib/update_menuentry.pl">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File>
		<File Path="/opt/tbootxm/lib/remove_menuentry.pl">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File>
		<File Path="/opt/tbootxm/initrd_hooks/tcb">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File>
		<File Path="/opt/tbootxm/mkinitrd_files/setup-measure_host.sh">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File>
		<Dir Exclude="" Include=".*" Path="/opt/trustagent/bin">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir>
		<File Path="/opt/trustagent/bin/module_analysis.sh">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File>
		<File Path="/opt/trustagent/bin/module_analysis_da.sh">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File>
		<File Path="/opt/trustagent/bin/module_analysis_da_tcg.sh">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File>
		<CumulativeHash>fc898764d5adb9053136a90e2ecdf2202e0f7fa58ff4a0e73d9e115804bc7d6e362b170aa358b996f016d915bd017e06</CumulativeHash>
	 </Measurement>`

	testCustomMeasurementXml = `<?xml version="1.0" encoding="UTF-8"?>
	 <Measurement xmlns="lib:wml:measurements:1.0" Label="New_Flavor" Uuid="5aed8104-f68b-40a1-b8f1-b646ecf33b40" DigestAlg="SHA384">
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/bin">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/dracut_files">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/initrd_hooks">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/lib">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir>
		<Dir Exclude="" Include=".*" Path="/opt/tbootxm/mkinitrd_files">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir>
		<File Path="/opt/tbootxm/bin/tpmextend">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File>
		<File Path="/opt/tbootxm/bin/measure">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File>
		<File Path="/opt/tbootxm/bin/configure_host.sh">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File>
		<File Path="/opt/tbootxm/bin/generate_initrd.sh">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File>
		<File Path="/opt/tbootxm/bin/measure_host">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File>
		<File Path="/opt/tbootxm/bin/tboot-xm-uninstall.sh">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File>
		<File Path="/opt/tbootxm/bin/functions.sh">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File>
		<File Path="/opt/tbootxm/dracut_files/check">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File>
		<File Path="/opt/tbootxm/dracut_files/install">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File>
		<File Path="/opt/tbootxm/dracut_files/module-setup.sh">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File>
		<File Path="/opt/tbootxm/lib/libwml.so">4b33910d5d03045275c2e8593f8bebefc2d4689c575a198a516121b25f44269107fb5075d1b5d9b35cf0b1da56b9e1e9</File>
		<File Path="/opt/tbootxm/lib/create_menuentry.pl">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File>
		<File Path="/opt/tbootxm/lib/update_menuentry.pl">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File>
		<File Path="/opt/tbootxm/lib/remove_menuentry.pl">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File>
		<File Path="/opt/tbootxm/initrd_hooks/tcb">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File>
		<File Path="/opt/tbootxm/mkinitrd_files/setup-measure_host.sh">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File>
		<Dir Exclude="" Include=".*" Path="/opt/trustagent/bin">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir>
		<File Path="/opt/trustagent/bin/module_analysis.sh">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File>
		<File Path="/opt/trustagent/bin/module_analysis_da.sh">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File>
		<File Path="/opt/trustagent/bin/module_analysis_da_tcg.sh">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File>
		<CumulativeHash>fc898764d5adb9053136a90e2ecdf2202e0f7fa58ff4a0e73d9e115804bc7d6e362b170aa358b996f016d915bd017e06</CumulativeHash>
	 </Measurement>`

	testSoftwareFlavor = `{
		 "meta": {
			 "schema": {
				 "uri": "lib:wml:measurements:1.0"
			 },
			 "id": "5aed8104-f68b-40a1-b8f1-b646ecf33b40",
			 "description": {
				 "flavor_part": "SOFTWARE",
				 "label": "ISecL_Default_Application_Flavor_v2.0_TPM2.0",
				 "digest_algorithm": "SHA384"
			 }
		 },
		 "software": {
			 "measurements": {
				 "opt-tbootxm-bin": {
					 "type": "directoryMeasurementType",
					 "value": "b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a",
					 "Path": "/opt/tbootxm/bin",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-tbootxm-dracut_files": {
					 "type": "directoryMeasurementType",
					 "value": "1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232",
					 "Path": "/opt/tbootxm/dracut_files",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-tbootxm-initrd_hooks": {
					 "type": "directoryMeasurementType",
					 "value": "77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7",
					 "Path": "/opt/tbootxm/initrd_hooks",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-tbootxm-lib": {
					 "type": "directoryMeasurementType",
					 "value": "b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb",
					 "Path": "/opt/tbootxm/lib",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-tbootxm-mkinitrd_files": {
					 "type": "directoryMeasurementType",
					 "value": "6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247",
					 "Path": "/opt/tbootxm/mkinitrd_files",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-tbootxm-bin-tpmextend": {
					 "type": "fileMeasurementType",
					 "value": "b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55",
					 "Path": "/opt/tbootxm/bin/tpmextend"
				 },
				 "opt-tbootxm-bin-measure": {
					 "type": "fileMeasurementType",
					 "value": "c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1",
					 "Path": "/opt/tbootxm/bin/measure"
				 },
				 "opt-tbootxm-bin-configure_host.sh": {
					 "type": "fileMeasurementType",
					 "value": "8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c",
					 "Path": "/opt/tbootxm/bin/configure_host.sh"
				 },
				 "opt-tbootxm-bin-generate_initrd.sh": {
					 "type": "fileMeasurementType",
					 "value": "4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4",
					 "Path": "/opt/tbootxm/bin/generate_initrd.sh"
				 },
				 "opt-tbootxm-bin-measure_host": {
					 "type": "fileMeasurementType",
					 "value": "7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a",
					 "Path": "/opt/tbootxm/bin/measure_host"
				 },
				 "opt-tbootxm-bin-tboot-xm-uninstall.sh": {
					 "type": "fileMeasurementType",
					 "value": "7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59",
					 "Path": "/opt/tbootxm/bin/tboot-xm-uninstall.sh"
				 },
				 "opt-tbootxm-bin-functions.sh": {
					 "type": "fileMeasurementType",
					 "value": "8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0",
					 "Path": "/opt/tbootxm/bin/functions.sh"
				 },
				 "opt-tbootxm-dracut_files-check": {
					 "type": "fileMeasurementType",
					 "value": "6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1",
					 "Path": "/opt/tbootxm/dracut_files/check"
				 },
				 "opt-tbootxm-dracut_files-install": {
					 "type": "fileMeasurementType",
					 "value": "e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a",
					 "Path": "/opt/tbootxm/dracut_files/install"
				 },
				 "opt-tbootxm-dracut_files-module-setup.sh": {
					 "type": "fileMeasurementType",
					 "value": "0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb",
					 "Path": "/opt/tbootxm/dracut_files/module-setup.sh"
				 },
				 "opt-tbootxm-lib-libwml.so": {
					 "type": "fileMeasurementType",
					 "value": "4b33910d5d03045275c2e8593f8bebefc2d4689c575a198a516121b25f44269107fb5075d1b5d9b35cf0b1da56b9e1e9",
					 "Path": "/opt/tbootxm/lib/libwml.so"
				 },
				 "opt-tbootxm-lib-create_menuentry.pl": {
					 "type": "fileMeasurementType",
					 "value": "79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e",
					 "Path": "/opt/tbootxm/lib/create_menuentry.pl"
				 },
				 "opt-tbootxm-lib-update_menuentry.pl": {
					 "type": "fileMeasurementType",
					 "value": "cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e",
					 "Path": "/opt/tbootxm/lib/update_menuentry.pl"
				 },
				 "opt-tbootxm-lib-remove_menuentry.pl": {
					 "type": "fileMeasurementType",
					 "value": "baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c",
					 "Path": "/opt/tbootxm/lib/remove_menuentry.pl"
				 },
				 "opt-tbootxm-initrd_hooks-tcb": {
					 "type": "fileMeasurementType",
					 "value": "430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98",
					 "Path": "/opt/tbootxm/initrd_hooks/tcb"
				 },
				 "opt-tbootxm-mkinitrd_files-setup-measure_host.sh": {
					 "type": "fileMeasurementType",
					 "value": "2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc",
					 "Path": "/opt/tbootxm/mkinitrd_files/setup-measure_host.sh"
				 },
				 "opt-trustagent-bin": {
					 "type": "directoryMeasurementType",
					 "value": "3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75",
					 "Path": "/opt/trustagent/bin",
					 "Include": ".*",
					 "Exclude": ""
				 },
				 "opt-trustagent-bin-module_analysis.sh": {
					 "type": "fileMeasurementType",
					 "value": "2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9",
					 "Path": "/opt/trustagent/bin/module_analysis.sh"
				 },
				 "opt-trustagent-bin-module_analysis_da.sh": {
					 "type": "fileMeasurementType",
					 "value": "2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d",
					 "Path": "/opt/trustagent/bin/module_analysis_da.sh"
				 },
				 "opt-trustagent-bin-module_analysis_da_tcg.sh": {
					 "type": "fileMeasurementType",
					 "value": "0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242",
					 "Path": "/opt/trustagent/bin/module_analysis_da_tcg.sh"
				 }
			 },
			 "cumulative_hash": "fc898764d5adb9053136a90e2ecdf2202e0f7fa58ff4a0e73d9e115804bc7d6e362b170aa358b996f016d915bd017e06"
		 }
	 }`

	testInvalidSoftwareFlavor = `{
		"meta": {
			"schema": {
				"uri": "lib:wml:measurements:1.0"
			},
			"id": "5aed8104-f68b-40a1-b8f1-b646ecf33b40",
			"description": {
				"flavor_part": "SOFTWARE",
				"label": "",
				"digest_algorithm": "SHA384"
			}
		},
		"software": {
		}
	}`
)

const (
	testIntegrityMeasurementsXml = `<?xml version= "1.0" encoding= "UTF-8" standalone= "yes" ?>
 <Measurement xmlns= "lib:wml:measurements:1.0" Label= "ISecL_Default_Application_Flavor_v1.0_TPM2.0" Uuid= "ff353e08-a5f0-4e32-b054-80ff79720d7d" DigestAlg= "SHA384">
	 <Dir Exclude= "" Include= ".*" Path= "/opt/tbootxm/bin">b0d5cba0bb12d69d8dd3e92bdad09d093a34dd4ea30aea63fb31b9c26d9cbf0e84016fa9a80843b473e1493a427aa63a</Dir>
	 <Dir Exclude= "" Include= ".*" Path= "/opt/tbootxm/dracut_files">1d9c8eb15a49ea65fb96f2b919c42d5dfd30f4e4c1618205287345aeb4669d18113fe5bc87b033aeef2aeadc2e063232</Dir>
	 <Dir Exclude= "" Include= ".*" Path= "/opt/tbootxm/initrd_hooks">77b913422748a8e62f0720d739d54b2fa7856ebeb9e76fab75c41c375f2ad77b7b9ec5849b20d857e24a894a615d2de7</Dir>
	 <Dir Exclude= "" Include= ".*" Path= "/opt/tbootxm/lib">b03eb9d3b6fa0d338fd4ef803a277d523ab31db5c27186a283dd8d1fe0e7afca9bf26b31b1099833b0ba398dbe3c02fb</Dir>
	 <Dir Exclude= "" Include= ".*" Path= "/opt/tbootxm/mkinitrd_files">6928eb666f6971af5da42ad785588fb9464465b12c78f7279f46f9f8e04ae428d4872e7813671a1390cc8ed433366247</Dir>
	 <File Path= "/opt/tbootxm/bin/tpmextend">b936d9ec4b8c7823efb01d946a7caa074bdfffdbd11dc20108ba771b8ef65d8efc72b559cd605b1ba0d70ef99e84ba55</File>
	 <File Path= "/opt/tbootxm/bin/measure">c72551ddfdfab6ec901b7ed8dc28a1b093793fd590d2f6c3b685426932013ca11a69aeb3c04a31278829f653a24deeb1</File>
	 <File Path= "/opt/tbootxm/bin/configure_host.sh">8675ca78238f0cf6e09d0d20290a7a2b9837e2a1c19a4a0a7a8c226820c33b6a6538c2f94bb4eb78867bd1a87a859a2c</File>
	 <File Path= "/opt/tbootxm/bin/generate_initrd.sh">4708ed8233a81d6a17b2c4b74b955f27612d2cc04730ad8919618964209ce885cea9011e00236de56a2239a524044db4</File>
	 <File Path= "/opt/tbootxm/bin/measure_host">7455104eb95b1ee1dfb5487d40c8e3a677f057da97e2170d66a52b555239a4b539ca8122ee25b33bb327373aac4e4b7a</File>
	 <File Path= "/opt/tbootxm/bin/tboot-xm-uninstall.sh">7450bc939548eafc4a3ba9734ad1f96e46e1f46a40e4d12ad5b5f6b5eb2baf1597ade91edb035d8b5c1ecc38bde7ee59</File>
	 <File Path= "/opt/tbootxm/bin/functions.sh">8526f8aedbe6c4bde3ba331b0ce18051433bdabaf8991a269aff7a5306838b13982f7d1ead941fb74806fc696fef3bf0</File>
	 <File Path= "/opt/tbootxm/dracut_files/check">6f5949b86d3bf3387eaff8a18bb5d64e60daff9a2568d0c7eb90adde515620b9e5e9cd7d908805c6886cd178e7b382e1</File>
	 <File Path= "/opt/tbootxm/dracut_files/install">e2fc98a9292838a511d98348b29ba82e73c839cbb02051250c8a8ff85067930b5af2b22de4576793533259fad985df4a</File>
	 <File Path= "/opt/tbootxm/dracut_files/module-setup.sh">0a27a9e0bff117f30481dcab29bb5120f474f2c3ea10fa2449a9b05123c5d8ce31989fcd986bfa73e6c25c70202c50cb</File>
	 <File Path= "/opt/tbootxm/lib/libwml.so">56a04d0f073f0eb2a4f851ebcba79f7080553c27fa8d1f7d4a767dc849015c9cc6c9abe937d0e90d73de27814f28e378</File>
	 <File Path= "/opt/tbootxm/lib/create_menuentry.pl">79770fb02e5a8f6b51678bde4d017f23ac811b1a9f89182a8b7f9871990dbbc07fd9a0578275c405a02ac5223412095e</File>
	 <File Path= "/opt/tbootxm/lib/update_menuentry.pl">cb6754eb6f2e39e43d420682bc91c83b38d63808b603c068a3087affb856703d3ae564892ac837cd0d4453e41b2a228e</File>
	 <File Path= "/opt/tbootxm/lib/remove_menuentry.pl">baf4f9b63ab9bb1e8616e3fb037580e38c0ebd4073b3b7b645e0e37cc7f0588f4c5ed8b744e9be7689aa78d23df8ec4c</File>
	 <File Path= "/opt/tbootxm/initrd_hooks/tcb">430725e0cb08b290897aa850124f765ae0bdf385e6d3b741cdc5ff7dc72119958fbcce3f62d6b6d63c4a10c70c18ca98</File>
	 <File Path= "/opt/tbootxm/mkinitrd_files/setup-measure_host.sh">2791f12e447bbc88e25020ddbf5a2a8693443c5ca509c0f0020a8c7bed6c813cd62cb4c250c88491f5d540343032addc</File>
	 <Dir Exclude= "" Include= ".*" Path= "/opt/trustagent/bin">3519466d871c395ce1f5b073a4a3847b6b8f0b3e495337daa0474f967aeecd48f699df29a4d106288f3b0d1705ecef75</Dir>
	 <File Path= "/opt/trustagent/bin/module_analysis.sh">2327e72fa469bada099c5956f851817b0c8fa2d6c43089566cacd0f573bf62e7e8dd10a2c339205fb16c3956db6518a9</File>
	 <File Path= "/opt/trustagent/bin/module_analysis_da.sh">2a99c3e80e99d495a6b8cce8e7504af511201f05fcb40b766a41e6af52a54a34ea9fba985d2835aef929e636ad2a6f1d</File>
	 <File Path= "/opt/trustagent/bin/module_analysis_da_tcg.sh">0f47a757c86e91a3a175cd6ee597a67f84c6fec95936d7f2c9316b0944c27cb72f84e32c587adb456b94e64486d14242</File>
	 <CumulativeHash>7425a5806dc8a5aacd508e4d6866655bf475947cc8bb630a03ff42b898ee8a7d8fd3ca71c3e1dacdc0f375bcbaf11efc</CumulativeHash>
 </Measurement>`
)
