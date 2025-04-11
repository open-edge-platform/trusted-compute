/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import "github.com/beevik/etree"

func responseXML(id, dst, irt, issueInstant string) *etree.Element {
	r := etree.NewElement(responseTag)
	r.CreateAttr(samlpAttr, samlpVal)
	r.CreateAttr(samlAttr, samlVal)
	r.CreateAttr(versionAttr, versionVal)

	r.CreateAttr(idAttr, id)
	r.CreateAttr(issueInstantAttr, issueInstant)
	r.CreateAttr(responseDestinationAttr, dst)
	r.CreateAttr(responseInResponseToAttr, irt)
	return r
}

func issuerXML(i string) *etree.Element {
	r := etree.NewElement(issuerTag)
	r.CreateText(i)
	return r
}

func statusXML(status string) *etree.Element {
	r := etree.NewElement(statusTag)
	statusCode := r.CreateElement(statusCodeTag)
	statusCode.CreateAttr(statusCodeAttr, status)
	return r
}

func assertionXML(id, issueInstant string) *etree.Element {
	r := etree.NewElement(assertionTag)
	r.CreateAttr(samlpAttr, samlpVal)
	r.CreateAttr(samlAttr, samlVal)
	r.CreateAttr(xsiAttr, xsiVal)
	r.CreateAttr(xsAttr, xsVal)
	r.CreateAttr(versionAttr, versionVal)

	r.CreateAttr(idAttr, id)
	r.CreateAttr(issueInstantAttr, issueInstant)
	return r
}

func subjectXML() *etree.Element {
	r := etree.NewElement(subjectTag)
	return r
}

func nameIDXML(nameID, spName, fmt string) *etree.Element {
	r := etree.NewElement(subjectNameIDTag)
	r.CreateText(nameID)
	if spName != "" {
		r.CreateAttr(subjectNameIDSPNameQualifierAttr, spName)
	}
	r.CreateAttr(subjectNameIDFormatAttr, fmt)
	return r
}

func subjectConfirmationXML(m string) *etree.Element {
	r := etree.NewElement(subjectConfirmationTag)
	r.CreateAttr(subjectConfirmationMethodAttr, m)
	return r
}

func subjectConfirmationDataXML(nb, na, recipient, irt string) *etree.Element {
	r := etree.NewElement(subjectConfirmationDataTag)
	createAttr(r, subjectConfirmationDataNotOnOrAfterAttr, na)
	createAttr(r, subjectConfirmationDataNotBefore, nb)
	createAttr(r, subjectConfirmationDataRecipientAttr, recipient)
	createAttr(r, subjectConfirmationDataInResponseToAttr, irt)
	return r
}

func conditionsXML(nb, na string) *etree.Element {
	r := etree.NewElement(conditionTag)
	createAttr(r, conditionNotBeforeAttr, nb)
	createAttr(r, conditionNotOnOrAfterAttr, na)
	return r
}

func audienceRestrictionXML() *etree.Element {
	r := etree.NewElement(conditionAudiencerestrictionTag)
	return r
}

func audienceXML(a string) *etree.Element {
	r := etree.NewElement(conditionAudienceTag)
	r.CreateText(a)
	return r
}

func attributeStatementXML() *etree.Element {
	r := etree.NewElement(attributeStatementTag)
	return r
}

func attributeXML(n, nf string) *etree.Element {
	r := etree.NewElement(attributeTag)
	r.CreateAttr(attributeNameAttr, n)
	r.CreateAttr(attributeNameFormatAttr, nf)
	return r
}

func attributeValueXML(val string) *etree.Element {
	r := etree.NewElement(attributeValueTag)
	r.CreateAttr(attributeValueXSITypeAttr, attributeValueXSITypeVal)
	r.CreateText(val)
	return r
}

func createAttr(e *etree.Element, k, v string) {
	if e != nil && v != "" {
		e.CreateAttr(k, v)
	}
}
