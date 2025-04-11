/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package controllers_test

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	consts "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/controllers"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/mocks"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/domain/models"
	hvsRoutes "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/hvs/router"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/crypt"
	wlaModel "github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/model/wlagent"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var certStore *crypt.CertificatesStore

var _ = BeforeSuite(func() {
	//Generate Privacyca cert
	certStore, _ = crypt.LoadCertificates(mocks.NewFakeCertificatesPathStore(), models.GetUniqueCertTypes())
	caCertDer, caKeyDer, _ := crypt.CreateKeyPairAndCertificate(consts.DefaultPrivacyCaIdentityIssuer, "", consts.DefaultKeyAlgorithm, consts.DefaultKeyLength)
	caCert, _ := x509.ParseCertificate(caCertDer)
	var caCerts []x509.Certificate
	caCerts = append(caCerts, *caCert)
	caKey, _ := x509.ParsePKCS8PrivateKey(caKeyDer)
	(*certStore)[models.CaCertTypesPrivacyCa.String()].Key = caKey
	(*certStore)[models.CaCertTypesPrivacyCa.String()].Certificates = caCerts
})

var _ = AfterSuite(func() {
	err := os.RemoveAll("../domain/mocks/resources/aik-reqs-dir")
	Expect(err).NotTo(HaveOccurred())
})

var _ = Describe("CertifyHostKeysController", func() {
	var router *mux.Router
	var w *httptest.ResponseRecorder
	var ecStore mocks.MockTpmEndorsementStore
	var certifyHostKeysController *controllers.CertifyHostKeysController
	var aikcert []byte
	var requireEKCertForHostProvision = false
	// modulus and aikName required for aik certificate generation
	modulus, _ := base64.StdEncoding.DecodeString("musrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQ==")
	aikName, _ := base64.StdEncoding.DecodeString("AAuTbAaKYOG2opc4QXq")
	n := new(big.Int)
	n.SetBytes(modulus)
	aikPubKey := rsa.PublicKey{N: n, E: 65537}

	BeforeEach(func() {
		certifyHostAiksController := controllers.NewCertifyHostAiksController(certStore, &ecStore, 2, "", true, requireEKCertForHostProvision)
		caKey := (*certStore)[models.CaCertTypesPrivacyCa.String()].Key
		caCert := &(*certStore)[models.CaCertTypesPrivacyCa.String()].Certificates[0]
		// Generate aik certificate
		var err error
		aikcert, err = certifyHostAiksController.CertifyAik(&aikPubKey, aikName, caKey.(*rsa.PrivateKey), caCert, 2)
		Expect(err).NotTo(HaveOccurred())
		router = mux.NewRouter()
		certifyHostKeysController = controllers.NewCertifyHostKeysController(certStore)
	})

	Describe("Create Binding key certificate", func() {
		Context("Provide valid data in request", func() {
			It("Return Binding key certificate", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-binding-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide invalid data in request", func() {
			It("Should get HTTP Status: 400", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-binding-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide invalid Content-Type in request", func() {
			It("Should get HTTP Status: 415", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGT5nQAAAAgAAAAAAQAHACgACDIAACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8RkACIACyjbYjRmoPAu54z17ffnj+YxzjFx3yO6T2fqKRKy25vc")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIAC/gUMncc7bnLWVlrtGaGT0WVlFXdxNwNVJW1DT1it8Rk")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-binding-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJwt)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide invalid body content in request", func() {
			It("Should get HTTP Status: 400", func() {

				router.Handle("/rpc/certify-host-binding-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifyBindingKey))).Methods(http.MethodPost)

				jsonData := `{
					"public_key_modulus": "ARYAAQALAAIAcgAAABAAEAgAAAAAAAEAnY4+SdHJYtd2cWgZWJPZYlG77k4nty/4qTXW7ovbx08PCRI2XtiW3x8DaGEOsjpv43vc4GBXOyAP/zZxCBBUTnh8ZxbrQY33vEvK51phPC1ADabMpcmvgntNXOUbYOL95raQpAbA0+ksKpHlA0s+Yx6T5AsLypCYVoCQ+GQoN0pQu9JTmhlo7/+KVP87hmqMiziKr3dYrBDrDlwDd1+UgrN6UvweHNOtct5xKkXa5WCF2GrXTaDZNZpHyL6AXtblGkrnVFbfNGiIuOy1717YqjyCEikXmj1Ar67XogGS0/KG1Aug2C2xEI1wDEZUvkpHg9rU8AAbWhkp756xKFhIcw==",
					"tpm_certify_key": "f1RDR4AXACIAC9foCXDLC4ZwjN9cSdVhjHTnwqFxpPi4/f3Bg5W1BmHRAAQA/1WqAAAAAIRk+Z0AAAAIAAAAAAEABwAoAAgyAAAiAAv4FDJ3HO25y1lZa7Rmhk9FlZRV3cTcDVSVtQ09YrfEZAAiAAso22I0ZqDwLueM9e3354/mMc4xcd8juk9n6ikSstub3A==",
					"tpm_certify_key_signature": "ABQACwEAdo8QAc8zd0IVw9m8bvwG3d5fUdF2QJCvbBqSYld/yu5PrAAwqOHot60PyZyEzKyaJVDQ7jCTllMe05/myVbXALVw1/dDxbLFkqBHhAhwLU57jeLcV6jVUuPhhk6KSuAuASzuQHbTqPkzwda/arBvhroCXPFAO6/VWMeXhZMbF42o6p4mCqzMQyVJ6MeXVFmpvzDTOBSkD799z9om6WIp/He0isg+5UNj+oFV0PSmT9DqUrzxoVvVYqzP17FYSdIeR8jKWLLdOv0+vtTirL9CrM+WT0jotMJRaayT+nKtaEVw0IjfY+NhiLY0rZH94UOJZrxNh968ZI1qQbyNcTaalA==",
					"aik_der_certificate": "MIIDRDCCAaygAwIBAgIRAJ1rPzpeGPSpZCKQyjdw48AwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEChMLaHZzLXBjYS1haWswHhcNMjIwNTA0MDkzNzMyWhcNMjQwNTA0MDkzNzMyWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmusrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQIDAQABoyMwITAfBgNVHSMEGDAWgBTlSY6Zl0bI3yS8iLJMyvphCyv4MjANBgkqhkiG9w0BAQsFAAOCAYEA3F4CEHUq9HVk7UhNW5fkuVJ9TUtc3cjkiP4vNNNb5lsdHCRnYcPiZFgNLMJ+gr5XGUVOrYWvBm0vFJ6kfQAzgEedI+Hs46qLCNZFfwaZAfOmi/lXYpagkMMf9mGCtRxhKB02QIuDtcHUM8blKbNaCvYJKQ58D1ZwI12hI/sXh5+a5Y1GObjmogEtuRa7SAzAs36+UaOOIhIdOEiaf7JRRGdChZBwL9f8NU/IGg0E7lwIKYeVh1VnGdAdE/ySjwrmdbxbe7fc9+JmyruL+1Ifx3MtCQwvQeQfuDiZEfJFIcOo8WDP88+xBcWN77itXsAmXZUNtuwFspXG7nmktwS/Yj0T4mVjmh9VpsgstE2zoGlyicYUqKX13/E12NkyXWW9yh9Olr0/P2Fg4T7sb6UXHRSLclbEUcITigPwlgEKYZMoqF8YMMO9Ae6k5lhrT9J5HXq9ndL6SXoJIwVg1YJKkA7m71S5GL7IQz5WOdp9Ia3pKBSpLSeCpxusaHuorYb7",
					"name_digest": "IgAL+BQydxztuctZWWu0ZoZPRZWUVd3E3A1UlbUNPWK3xGQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"tpm_version: "2.0",
					"operating_system": "Linux"
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-binding-key",
					strings.NewReader(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

	})

	Describe("Create Signing key certificate", func() {
		Context("Provide valid data in request", func() {
			It("Return Signing key certificate", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusCreated))
			})
		})

		Context("Provide invalid tpmCertifyKey in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide invalid aikcert in request", func() {
			It("Should get HTTP Status: 400", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("CHJ/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				aikcert = append(aikcert, []byte{0x03, 0x04}...)
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})

		Context("Provide invalid Content-Type in request", func() {
			It("Shout not return Signing key certificate - Shoud return 415", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods(http.MethodPost)

				publicKeyModulus, _ := base64.StdEncoding.DecodeString("ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==")
				tpmCertifyKey, _ := base64.StdEncoding.DecodeString("AJH/VENHgBcAIgAL1+gJcMsLhnCM31xJ1WGMdOfCoXGk+Lj9/cGDlbUGYdEABAD/VaoAAAAAhGTwPgAAAAgAAAAAAQAHACgACDIAACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mmACIACwtc+e+3ebKvGNTVz/gsvHQeC4R3fDIzRnmQ2ANXgn7O")
				tpmCertifyKeySignature, _ := base64.StdEncoding.DecodeString("ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==")
				nameDigest, _ := base64.StdEncoding.DecodeString("ACIACwchoioo7NUmNBdN9SiGaeaoxJE47W5w6FoNGCGTv3mm")
				regKeyInfoPayload := wlaModel.RegisterKeyInfo{
					PublicKeyModulus:       publicKeyModulus,
					TpmCertifyKey:          tpmCertifyKey[2:],
					TpmCertifyKeySignature: tpmCertifyKeySignature,
					AikDerCertificate:      aikcert,
					NameDigest:             append(nameDigest[1:], make([]byte, 34)...),
					TpmVersion:             "2.0",
					OsType:                 "Linux",
				}
				jsonData, _ := json.Marshal(regKeyInfoPayload)

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-signing-key",
					bytes.NewBuffer(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJwt)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusUnsupportedMediaType))
			})
		})

		Context("Provide invalid RequestBody in request", func() {
			It("Shout not return Signing key certificate - Shoud return 400", func() {
				router.Handle("/rpc/certify-host-signing-key", hvsRoutes.ErrorHandler(hvsRoutes.JsonResponseHandler(certifyHostKeysController.CertifySigningKey))).Methods(http.MethodPost)
				jsonData := `{
					"public_key_modulus": "ARYAAQALAAQAcgAAABAAEAgAAAAAAAEAlr9jyEGbgkQvVQnU8SYaNvYULm0AfHjslyc/vtBSjMMJXAQahvYP2L/bOyGsRDBbGo2Wq3OpEzphmH66wIhVhltZVA6e04vaFPSEATABMTuv5WPAPNvaFITPFAtdoTcZGsajPELuhw1+2NXMr4BG141vos9nltKqZ36XMAh8Mxmrb0Y+o+yGQWJxWvtxbxc4Q39d77SxUDkxMQgdVwWFapIQs09xh8x8TbaTLed6sdVZNisdlMlNVdhyIb81bXyigkMjnkCckxvjrGUs8eC6ZO/Z13dOU+A2j7nGpu5wXAmknxXfBobdRbUaHF/acp0YVHA0FL2f/hcy2zQWEO2FaQ==",
					"tpm_certify_key": "/1RDR4AXACIAC9foCXDLC4ZwjN9cSdVhjHTnwqFxpPi4/f3Bg5W1BmHRAAQA/1WqAAAAAIRk8D4AAAAIAAAAAAEABwAoAAgyAAAiAAsHIaIqKOzVJjQXTfUohmnmqMSROO1ucOhaDRghk795pgAiAAsLXPnvt3myrxjU1c/4LLx0HguEd3wyM0Z5kNgDV4J+zg==",
					"tpm_certify_key_signature": "ABQACwEALTwMv8DuN1o/JAuOlR1poqQ193xnCAmHyKUBoHR9zRqvuwvwYwWF0c/LRN5fi3lwFt8p1HXU9k7gIiM6OEQlZqjcWsz6HEyWukbMijMX1XeX/c94Z4jFSceC5PrNsRZl6qHD2Jw0RpPTzKYJ/jB+KUec4AmWZlPNRI3ba3ukErHqxmlLqSJb6dLriIKXBXacRnpTZC3eok/bulpKfJpVEAEDsPwapoZIZfHEzCaR8RDpMq0NCE6scucPfv/za4POQNu4SoBPoZlcwENBmfoCq3C3hqIiZ4ZcwTXXPoYBDd2Gv+X0iUyaa0XVtO41feajM4BrIKEa7llWvOTrLgj0qQ==",
					"aik_der_certificate": "MIIDRDCCAaygAwIBAgIRAOvkzMv8cME4ZM0viViVR+EwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEChMLaHZzLXBjYS1haWswHhcNMjIwNTA0MDkyNjEwWhcNMjQwNTA0MDkyNjEwWjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmusrA8GOcUtcD3phno/e4XseAdzLG/Ff1qXBIZ/GWdQUKTvOQlUq5P+BJLD1ifp7bpyvXdpesnHZuhXpi4AM8D2uJYTs4MeamMJ2LKAu/zSk9IDz4Z4gnQACSGSWzqafXv8OAh6D7/EOjzUh/sjkZdTVjsKzyHGp7GbY+G+mt9/PdF1e4/TJlp41s6rQ6BAJ0mA4gNdkrJLW2iedM1MZJn2JgYWDtxej5wD6Gm7/BGD+Rn9wqyU4U6fjEsNqeXj0E0DtkreMAi9cAQuoagckvh/ru1o8psyzTM+Bk+EqpFrfg3nz4nDC+Nrz+IBjuJuFGNUUFbxC6FrdtX4c2jnQIQIDAQABoyMwITAfBgNVHSMEGDAWgBQoB/OyaoqF0C/shFsWs5X91nDboTANBgkqhkiG9w0BAQsFAAOCAYEAulJHZBaBSvFJZ+DUc8tXvo0trGxwxeYlRPtRakPQZuyuQXBRenb9WOy7lJZNsZENZTaM+x+itanzxBgZSKxkg39W9YILgkA4NYlkcKCdWRPfXlNux0/L9daKF2XQCjGf+BiXEZJFVkvm8gYFP8F6sRXMkFJR94VhNVCQOTPxFAyrEVL3tlLYQdogeR7RxQ9YXxQCss1v11pcpG9HEu1GMcztpxFLWYeUFmsypkq5yQmJzSlPs4swDBzQke8OM0cEZiW0CQVeeulsBQBeZ8ijLMzsKQ7hGVqZ+TX7XwFwIhHOCfh+cHeOZCVwszLajqEw9SpaTVLTwT0GAzIVtO8PeLSDQKF78CqnXf1zCxcQPeteIzU42EdBHjJkj8rm+/BFsqJ5n0XxoFxzP0i9KtXFxb4YRk3gBhE076T5wglGtIlakC+8yhoz5mPWR9CMmJ+Dxe+iQ7aMjUftySk9gyeWGzJW5PkVWG27GOR0PoDeJs9ttB+xk8vd59QfadohIp8c",
					"name_digest: "IgALByGiKijs1SY0F031KIZp5qjEkTjtbnDoWg0YIZO/eaYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
					"tpm_version": "2.0",
					"operating_system": Linux
				}`

				req, err := http.NewRequest(
					http.MethodPost,
					"/rpc/certify-host-signing-key",
					strings.NewReader(jsonData),
				)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Set("Content-Type", constants.HTTPMediaTypeJson)
				req.Header.Set("Accept", constants.HTTPMediaTypeJson)
				w = httptest.NewRecorder()
				router.ServeHTTP(w, req)
				Expect(w.Code).To(Equal(http.StatusBadRequest))
			})
		})
	})
})

func TestNewCertifyHostKeysController(t *testing.T) {
	type args struct {
		certStore *crypt.CertificatesStore
	}
	CertStore := mocks.NewFakeCertificatesStore()
	tests := []struct {
		name string
		args args
		want *controllers.CertifyHostKeysController
	}{
		{
			name: "Valid certificate store",
			args: args{
				certStore: CertStore,
			},
			want: &controllers.CertifyHostKeysController{
				CertStore: CertStore,
			},
		},
		{
			name: "Invalid certificate store",
			args: args{
				certStore: &crypt.CertificatesStore{
					models.CaCertTypesPrivacyCa.String(): &crypt.CertificateStore{
						Key:          nil,
						Certificates: nil,
					},
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewCertifyHostKeysController(tt.args.certStore); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertifyHostKeysController() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCertifyHostAiksController(t *testing.T) {
	type args struct {
		certStore                     *crypt.CertificatesStore
		ecstore                       domain.TpmEndorsementStore
		aikCertValidity               int
		aikReqsDir                    string
		isCheckEkCertRevoke           bool
		requireEKCertForHostProvision bool
	}
	var certStore crypt.CertificatesStore
	certs := &crypt.CertificateStore{
		Key:          &rsa.PrivateKey{},
		CertPath:     "test",
		Certificates: []x509.Certificate{x509.Certificate{}},
	}
	certStore = make(map[string]*crypt.CertificateStore, 0)
	certStore[models.CaCertTypesPrivacyCa.String()] = certs
	tests := []struct {
		name string
		args args
		want *controllers.CertifyHostAiksController
	}{
		{
			name: "Privacy Ca cert not found error",
			args: args{
				certStore: &crypt.CertificatesStore{},
			},
			want: nil,
		},
		{
			name: "Endorsement ca cert not found error",
			args: args{
				certStore: &certStore,
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := controllers.NewCertifyHostAiksController(tt.args.certStore, tt.args.ecstore, tt.args.aikCertValidity, tt.args.aikReqsDir, tt.args.isCheckEkCertRevoke, tt.args.requireEKCertForHostProvision); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewCertifyHostAiksController() = %v, want %v", got, tt.want)
			}
		})
	}
}
