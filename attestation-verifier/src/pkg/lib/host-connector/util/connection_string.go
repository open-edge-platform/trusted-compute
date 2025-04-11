/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package util

import (
	"fmt"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/common/validation"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/constants"
	"github.com/open-edge-platform/trusted-compute/attestation-verifier/src/pkg/lib/host-connector/types"
	"github.com/pkg/errors"
	"net"
	"net/url"
	"strings"
)

func GetConnectorDetails(connectionString string) (types.VendorConnector, error) {

	log.Trace("util/connection_string:GetConnectorDetails() Entering")
	defer log.Trace("util/connection_string:GetConnectorDetails() Leaving")
	var vendorConnector types.VendorConnector
	var vendorURL string
	var vendorName string

	// use a regex to eliminate all invalid connection strings
	if err := validation.ValidateConnectionString(connectionString); err != nil {
		return types.VendorConnector{}, err
	}

	vendor := GetVendorPrefix(connectionString)
	if vendor == constants.VendorUnknown {
		if connectionString != "" && (!strings.Contains(connectionString, ":") || strings.ToLower(connectionString[:strings.Index(connectionString, ":")]) != "https") {
			return types.VendorConnector{}, errors.New("Vendor provided at URL prefix is not supported")
		}
		vendor = GuessVendorFromURL(connectionString)
		vendorURL = connectionString
	} else {
		vendorName = strings.ToUpper(vendor.String())
		vendorURL = connectionString[len(vendorName)+1:]
	}
	vendorConnector.Url, vendorConnector.Configuration.Username, vendorConnector.Configuration.Password,
		vendorConnector.Configuration.Hostname = ParseConnectionString(vendorURL)

	if _, err := url.Parse(vendorConnector.Url); err != nil {
		return types.VendorConnector{}, err
	}
	vendorConnector.Vendor = vendor
	return vendorConnector, nil
}

func GuessVendorFromURL(connectionString string) constants.Vendor {

	log.Trace("util/connection_string:GuessVendorFromURL() Entering")
	defer log.Trace("util/connection_string:GuessVendorFromURL() Leaving")
	if strings.Contains(connectionString, "/sdk") {
		return constants.VendorVMware
	} else {
		return constants.VendorIntel
	}
}

func GetVendorPrefix(connectionString string) constants.Vendor {

	log.Trace("util/connection_string:GetVendorPrefix() Entering")
	defer log.Trace("util/connection_string:GetVendorPrefix() Leaving")
	if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.VendorIntel.String()+":")) {
		return constants.VendorIntel
	} else if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.VendorVMware.String()+":")) {
		return constants.VendorVMware
	} else if strings.HasPrefix(strings.ToLower(connectionString), strings.ToLower(constants.VendorMicrosoft.String()+":")) {
		return constants.VendorMicrosoft
	}
	return constants.VendorUnknown
}

func ParseConnectionString(vendorURL string) (string, string, string, string) {

	log.Trace("util/connection_string:ParseConnectionString() Entering")
	defer log.Trace("util/connection_string:ParseConnectionString() Leaving")
	urlEndIndex := strings.IndexAny(vendorURL, ";")
	var url string
	var hostname string
	var username string
	var password string
	if urlEndIndex != -1 {
		url = vendorURL[:urlEndIndex]
		username, password, hostname = parseCredentials(vendorURL[urlEndIndex:])
	} else {
		return vendorURL, "", "", ""
	}
	return url, username, password, hostname
}

func parseCredentials(credentials string) (string, string, string) {

	log.Trace("util/connection_string:parseCredentials() Entering")
	defer log.Trace("util/connection_string:parseCredentials() Leaving")
	splitCredentials := strings.Split(credentials, ";")
	var username string
	var password string
	var hostname string
	for _, credentials := range splitCredentials {
		if strings.Contains(credentials, "u=") {
			username = strings.Split(credentials, "=")[1]
		} else if strings.Contains(credentials, "p=") {
			password = strings.Split(credentials, "=")[1]
		} else if strings.Contains(credentials, "h=") {
			hostname = strings.Split(credentials, "=")[1]
		}
	}
	return username, password, hostname
}

// getHostIP verifies that the hostname provided in the connection string can be resolved to an IPV4 address
// since this will be required for the nonce verification
func GetHostIP(hostRef string) (string, error) {
	log.Trace("util/connection_string:GetHostIP() Entering")
	defer log.Trace("util/connection_string:GetHostIP() Leaving")

	// strip off the port number
	if strings.Contains(hostRef, ":") {
		hostRef = strings.Split(hostRef, ":")[0]
	}

	// at this point the provided IP Address could also be a hostname, so check if it is an IP
	hostIP := net.ParseIP(hostRef)
	if hostIP == nil {
		// DNS lookup as a last resort
		addrs, err := net.LookupHost(hostRef)
		if err != nil {
			return "", errors.Wrap(err, "util/connection_string:GetHostIP() Hostname provided in "+
				"connection string could not be mapped to an IP address")
		}
		log.Debugf("util/aik_quote_verifier:GetHostIP() possible addresses for %s - %s", hostRef, addrs)

		// convert the first address in the list to an IPV4 address and return
		hostIP = net.ParseIP(addrs[0])
		if hostIP.To4() == nil {
			log.Debugf("util/aik_quote_verifier:GetHostIP() %s is not a valid IPv4 address", hostIP.String())
			return "", fmt.Errorf("util/aik_quote_verifier:GetHostIP() Could not obtain a valid IPv4 address for %s", hostRef)
		}
	}

	return hostIP.String(), nil
}
