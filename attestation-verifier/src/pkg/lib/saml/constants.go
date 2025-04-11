/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

// tags shared between response and assertion
const (
	idAttr           = "ID"
	issueInstantAttr = "IssueInstant"

	versionAttr = "Version"
	versionVal  = "2.0"

	samlpAttr = "xmlns:samlp"
	samlpVal  = "urn:oasis:names:tc:SAML:2.0:protocol"

	samlAttr = "xmlns:saml"
	samlVal  = "urn:oasis:names:tc:SAML:2.0:assertion"

	xsiAttr = "xmlns:xsi"
	xsiVal  = "http://www.w3.org/2001/XMLSchema-instance"

	xsAttr = "xmlns:xsd"
	xsVal  = "http://www.w3.org/2001/XMLSchema"

	// Response/Issuer, Assertion/Issuer
	issuerTag = "saml:Issuer"

	issuerServiceNameTag = "IssuerServiceName"
)

// Response tag and attr
const (
	responseTag              = "samlp:Response"
	responseDestinationAttr  = "Destination"
	responseInResponseToAttr = "InResponseTo"
)

const (
	// Response/Status
	statusTag = "samlp:Status"

	// Response/Status/StatusCode
	statusCodeTag  = "samlp:StatusCode"
	statusCodeAttr = "Value"
)

// Assertion tags and attr
const (
	assertionTag = "saml:Assertion"
)

// assertion subject
const (
	// Assertion/Subject
	subjectTag = "saml:Subject"

	// Assertion/Subject/NameID
	subjectNameIDTag                 = "saml:NameID"
	subjectNameIDSPNameQualifierAttr = "SPNameQualifier"
	subjectNameIDFormatAttr          = "Format"

	// Assertion/Subject/SubjectConfirmation
	subjectConfirmationTag        = "saml:SubjectConfirmation"
	subjectConfirmationMethodAttr = "Method"

	// Assertion/Subject/SubjectConfirmation/SubjectConfirmationData
	subjectConfirmationDataTag              = "saml:SubjectConfirmationData"
	subjectConfirmationDataNotOnOrAfterAttr = "NotOnOrAfter"
	subjectConfirmationDataNotBefore        = "NotBefore"
	subjectConfirmationDataRecipientAttr    = "Recipient"
	subjectConfirmationDataInResponseToAttr = "InResponseTo"
)

// Assertion conditions
const (
	// Assertion/Subject/Conditions
	conditionTag              = "saml:Conditions"
	conditionNotBeforeAttr    = "NotBefore"
	conditionNotOnOrAfterAttr = "NotOnOrAfter"

	// Assertion/Subject/Conditions/AudienceRestriction
	conditionAudiencerestrictionTag = "saml:AudienceRestriction"

	// Assertion/Subject/Conditions/AudienceRestriction/Audience
	conditionAudienceTag = "saml:Audience"
)

// Assertion AuthnStatement
const (
	// Assertion/AuthnStatement
	authnStatementTag = "saml:AuthnStatement"

	authnStatementAuthnInstantAttr        = "saml:AuthnInstant"
	authnStatementSessionNotOnOrAfterAttr = "saml:SessionNotOnOrAfter"
	authnStatementSessionIndexAttr        = "saml:SessionIndex"

	// Assertion/AuthnStatement/AuthnContext
	authnContextTag = "saml:AuthnContext"

	// Assertion/AuthnStatement/AuthnContext/AuthnContextClassRef
	authnContextClassRefTag = "saml:AuthnContextClassRef"
)

const (
	// Assertion/AuthnStatement/AuthnContext/AttributeStatement
	attributeStatementTag = "saml:AttributeStatement"

	// Assertion/AuthnStatement/AuthnContext/AttributeStatement/Attribute
	attributeTag            = "saml:Attribute"
	attributeNameAttr       = "Name"
	attributeNameFormatAttr = "NameFormat"
	// Assertion/AuthnStatement/AuthnContext/AttributeStatement/Attribute/AttributeValue
	attributeValueTag         = "saml:AttributeValue"
	attributeValueXSITypeAttr = "xsi:type"
)

const (
	subjectConfirmationMethodVal = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"

	subjectNameIDFormatTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	subjectNameIDFormatUnspecified = "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"

	statusCodeSuccess         = "urn:oasis:names:tc:SAML:2.0:status:Success"
	statusCodeRequester       = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	statusCodeResponder       = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	statusCodeVersionMismatch = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"

	// all status code:
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samlpr/96b92662-9bf7-4910-ab16-e1c28bce962b
	// statusCodeAuthnFailed              = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	// statusCodeInvalidAttrNameOrValue   = "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
	// statusCodeInvalidNameIDPolicy      = "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy"
	// statusCodeNoAuthnContext           = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"
	// statusNoAvailableIDP               = "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP"
	// statusCodeNoPassive                = "urn:oasis:names:tc:SAML:2.0:status:NoPassive"
	// statusCodeNoSupportedIDP           = "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP"
	// statusCodePartialLogout            = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
	// statusCodeProxyCountExceeded       = "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded"
	// statusCodeRequestDenied            = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied"
	// statusCodeRequestUnsupported       = "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported"
	// statusCodeRequestVersionDeprecated = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
	// statusCodeRequestVersionTooHigh    = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
	// statusCodeRequestVersionTooLow     = "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow"
	// statusCodeResourceNotRecognized    = "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
	// statusCodeTooManyResponses         = "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses"
	// statusCodeUnknownAttrProfile       = "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile"
	// statusCodeUnknownPrincipal         = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	// statusCodeUnsupportedBinding       = "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"

	attributeNameFormatBasicVal = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

	attributeValueXSITypeVal = "xs:string"
)
