/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package hvs_test

import (
	"encoding/json"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/hvs"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var flavorgroupJson = `{
   "id":"ee37c360-7eae-4250-a677-6ee12adce8e2",
   "name":"hvs_flavorgroup_test3",
   "flavor_match_policy_collection":{
      "flavor_match_policies":[
         {
            "flavor_part":"PLATFORM",
            "match_policy":{
               "match_type":"ANY_OF",
               "required":"REQUIRED"
            }
         },
         {
            "flavor_part":"OS",
            "match_policy":{
               "match_type":"ANY_OF",
               "required":"REQUIRED"
            }
         },
         {
            "flavor_part":"HOST_UNIQUE",
            "match_policy":{
               "match_type":"LATEST",
               "required":"REQUIRED_IF_DEFINED"
            }
         },
         {
            "flavor_part":"SOFTWARE",
            "match_policy":{
               "match_type":"ALL_OF",
               "required":"REQUIRED"
            }
         }
      ]
   }
}`

var _ = Describe("FlavorGroup", func() {

	// Parse flavorgroup object
	Describe("Unmarshal flavorgroup json string", func() {
		Context("Provided a valid Flavorgroup json string", func() {
			It("Should be unmarshalled to Flavorgroup struct", func() {
				var fg hvs.FlavorGroup
				err := json.Unmarshal([]byte(flavorgroupJson), &fg)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("get match policy types map for each flavorgroup", func() {
		Context("Provided a valid Flavorgroup and get match policy details", func() {
			It("Should generate valid maps", func() {
				var fg hvs.FlavorGroup
				err := json.Unmarshal([]byte(flavorgroupJson), &fg)
				Expect(err).NotTo(HaveOccurred())
				fpMap, mtMap, plcyMap := fg.GetMatchPolicyMaps()
				Expect(len(fpMap)).Should(Equal(4))
				Expect(len(mtMap)).Should(Equal(3))
				Expect(len(plcyMap)).Should(Equal(2))
			})
		})
	})
})
