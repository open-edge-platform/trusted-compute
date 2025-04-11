/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package constants

//Roles and permissions
const (
	Administrator = "*:*:*"

	FlavorGroupCreate   = "flavorgroups:create"
	FlavorGroupRetrieve = "flavorgroups:retrieve"
	FlavorGroupSearch   = "flavorgroups:search"
	FlavorGroupDelete   = "flavorgroups:delete"

	CertifyAik = "host_aiks:certify"

	HostStatusRetrieve = "host_status:retrieve"
	HostStatusSearch   = "host_status:search"

	CaCertificatesCreate = "cacertificates:create"

	CertifyHostSigningKey = "host_signing_key_certificates:create"

	HostCreate   = "hosts:create"
	HostRetrieve = "hosts:retrieve"
	HostUpdate   = "hosts:store"
	HostDelete   = "hosts:delete"
	HostSearch   = "hosts:search"

	//FlavorTemplate Permissions.
	FlavorTemplateCreate   = "flavor-template:create"
	FlavorTemplateRetrieve = "flavor-template:retrieve"
	FlavorTemplateSearch   = "flavor-template:search"
	FlavorTemplateDelete   = "flavor-template:delete"

	FlavorCreate   = "flavors:create"
	FlavorRetrieve = "flavors:retrieve"
	FlavorSearch   = "flavors:search"
	FlavorDelete   = "flavors:delete"

	TagFlavorCreate        = "tag_flavors:create"
	HostUniqueFlavorCreate = "host_unique_flavors:create"

	SoftwareFlavorCreate = "software_flavors:create"
	SoftwareFlavorDeploy = "software_flavors:deploy"

	ESXiClusterCreate   = "esxi_clusters:create"
	ESXiClusterRetrieve = "esxi_clusters:retrieve"
	ESXiClusterSearch   = "esxi_clusters:search"
	ESXiClusterDelete   = "esxi_clusters:delete"

	TpmEndorsementCreate   = "tpm_endorsements:create"
	TpmEndorsementStore    = "tpm_endorsements:store"
	TpmEndorsementRetrieve = "tpm_endorsements:retrieve"
	TpmEndorsementSearch   = "tpm_endorsements:search"
	TpmEndorsementDelete   = "tpm_endorsements:delete"

	ReportCreate   = "reports:create"
	ReportRetrieve = "reports:retrieve"
	ReportSearch   = "reports:search"

	// AssetTagAPI
	TagCertificateCreate = "tag_certificates:create"
	TagCertificateDelete = "tag_certificates:delete"
	TagCertificateSearch = "tag_certificates:search"
	TagCertificateDeploy = "tag_certificates:deploy"

	// Tag Certificates Requests API
	TagCertificateRequestsStore = "tag_certificate_requests:store"
)
