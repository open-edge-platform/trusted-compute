/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package saml

import (
	"time"

	"github.com/beevik/etree"
	"github.com/google/uuid"
	"github.com/pkg/errors"
)

// there is no default rfc3339 time with millisecond precision in go
const rfc3339ms = "2006-01-02T15:04:05.999Z07:00"

type assertionFormatter interface {
	generateXMLTree(IssuerConfiguration) (*etree.Element, error)
}

type mapFormatter struct {
	userData map[string]string
}

func NewMapFormatter(data map[string]string) assertionFormatter {
	return &mapFormatter{
		userData: data,
	}
}

func (mf *mapFormatter) generateXMLTree(ic IssuerConfiguration) (*etree.Element, error) {
	// get default tree
	root, payload, err := assertionXMLTree(ic)
	if err != nil {
		return nil, err
	}
	// issuer service name
	e := attributeXML(issuerServiceNameTag, attributeNameFormatBasicVal)
	e.AddChild(attributeValueXML(ic.IssuerServiceName))
	payload.AddChild(e)
	// add content
	for k, v := range mf.userData {
		e := attributeXML(k, attributeNameFormatBasicVal)
		e.AddChild(attributeValueXML(v))
		payload.AddChild(e)
	}
	return root, nil
}

func assertionXMLTree(ic IssuerConfiguration) (*etree.Element, *etree.Element, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to generate random UUID for assertion")
	}
	issueTime := time.Now().UTC().Format(rfc3339ms)
	d := time.Duration(ic.ValiditySeconds) * time.Second
	validTime := time.Now().UTC().Add(d).Format(rfc3339ms)
	r := assertionXML(id.String(), issueTime)
	r.AddChild(issuerXML(ic.IssuerName))

	// subject
	subject := subjectXML()
	nameID := nameIDXML(ic.IssuerName, "", subjectNameIDFormatUnspecified)

	subjectConfirmation := subjectConfirmationXML(subjectConfirmationMethodVal)
	subjectConfirmationData := subjectConfirmationDataXML(issueTime, validTime, "", "")
	subjectConfirmNameID := nameIDXML("Intel Security Libraries", "", subjectNameIDFormatUnspecified)
	subjectConfirmation.AddChild(subjectConfirmationData)
	subjectConfirmation.AddChild(subjectConfirmNameID)

	subject.AddChild(nameID)
	subject.AddChild(subjectConfirmation)

	r.AddChild(subject)
	r.AddChild(conditionsXML(issueTime, validTime))
	as := attributeStatementXML()
	r.AddChild(as)
	return r, as, nil
}
