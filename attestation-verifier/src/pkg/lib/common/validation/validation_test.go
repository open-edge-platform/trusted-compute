/*
 * Copyright (C) 2025 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package validation

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateEnvList(t *testing.T) {
	a := assert.New(t)

	os.Setenv("GOENV_TEST1", "NOT IMPORTATN CONTENT")
	os.Setenv("GOENV_TEST2", "NOT IMPORTATN CONTENT")
	os.Setenv("GOENV_TEST3", "NOT IMPORTATN CONTENT")

	neededEnv := []string{"GOENV_TEST1", "GOENV_TEST2", "GOENV_TEST3"}
	missing, err := ValidateEnvList(neededEnv)

	a.Equal(nil, err)
	a.Equal(0, len(missing))

	moreThanNeededEnv := []string{"GOENV_TEST2", "GOENV_TEST3", "GOENV_TEST4", "GOENV_TEST5"}

	missing1, err1 := ValidateEnvList(moreThanNeededEnv)
	sampleErr := errors.New("One or more required environment variables are missing")

	a.Equal(sampleErr, err1)

	// should show [GOENV_TEST4:0 GOENV_TEST5:0]
	// run with with go test -v
	fmt.Println(missing1)
}

func TestValidateURL(t *testing.T) {
	a := assert.New(t)

	goodURL1 := "https://google.com"
	goodURL2 := "http://good.url.with.port:5566"
	goodURL3 := "https://good.url.https.with.port:5566"

	goodTests := []string{goodURL1, goodURL2, goodURL3}

	protocols := make(map[string]byte)
	protocols["http"] = 0
	protocols["https"] = 0

	for _, goodStr := range goodTests {
		err := ValidateURL(goodStr+"/tds/", protocols, "/tds/")
		a.Equal(nil, err)
	}

	goodURL4 := "https://server.com:443/v1/keys/438c7486-9827-4072-89c5-93ae4538114e/transfer"
	err := ValidateURL(goodURL4, protocols, "/v1/keys/438c7486-9827-4072-89c5-93ae4538114e/transfer")
	a.Equal(nil, err)

	badURL1 := "bad.url.without.protocol/tds/"
	badURL2 := "scheme://bad.url.with.wrong.protocol/tds/"
	badURL3 := "https://bad.url.with.path/tds/path/path/"
	badURL4 := "https://bad.url.with.query/tds/?query=haha"

	err1 := errors.New("Invalid base URL")
	err2 := errors.New("Unsupported protocol")
	err3 := errors.New("Invalid path in URL")
	err4 := errors.New("Unexpected inputs")

	badTests := []string{badURL1, badURL2, badURL3, badURL4}
	badResult := []error{err1, err2, err3, err4}

	for _, badStr := range badTests {
		err := ValidateURL(badStr, protocols, "/tds/")
		a.Contains(badResult, err)
	}
}

func TestValidateStrings(t *testing.T) {
	goodString1 := "/var/lib/nova/instances/"
	goodString2 := "abcd1234"
	goodString3 := "workload-agent"
	goodString4 := "cirros-x86.qcow2_enc"
	goodString5 := ""
	goodString6 := "cirros-enc.qcow2"

	goodStringValueArr := []string{goodString1, goodString2, goodString3, goodString4, goodString5, goodString6}
	err := ValidateStrings(goodStringValueArr)
	assert.NoError(t, err)

	badString1 := "fishy_symbols \" ` ' )))((*&^ "
	badString2 := "\" \" \" SELECT * FROM TABLE"
	badString3 := "<inputTag>"

	badStringValueArr := []string{badString1, badString2, badString3}
	err = ValidateStrings(badStringValueArr)
	assert.Error(t, err)
}

func TestValidatePemEncodedKey(t *testing.T) {

	goodString1 := "-----BEGIN CERTIFICATE----MIIEoDCCA4igAwIBAgIIHZR9rDPTS9IwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAxMQbXR3aWxzb24tcGNhLWFpazAeFw0xOTAzMDgwOTQ0MDJaFw0yOTAzMDUwOTQ0MDJaMCUxIzAhBgNVBAMMGkNOPUJpbmRpbmdfS2V5X0NlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvarJulWowk4Mr0CwJ8SMrGNvbHKryZmTgLFftnj7bwd7VUx0zACjwv0jObFAonocBMEO39hxhHeQWuyUB1OEuvt3Kzg40EG11PvsHttWM2rgYk88z+E7vsQrdHx08FLeN4T+SK9ML+uKDPFuQWLrzZ2irQxGznokn2aAz+zl8vIDkVjmVDw4I9D6/6hMAEaE4WGiznoPS1sEe6vyqPhOL9dQOrFzW5qC6JKNwPtuYIWg5VrhrxguTHe5vK7TpZxgbxjWbeSdiDAnNU7UdZM5QboJ8Ao7Oz54OtIqpUuIEXSzIaJ/Dbo0yXrYCJzcSDTpSDimitqfTiot9p6+pQSM8wIDAQABo4IB3DCCAdgwDgYDVR0PAQH/BAQDAgUgMIGdBgdVBIEFAwIpBIGR/1RDR4AXACIAC0y1Y5XeuPW1DaT1Y11paGPfMQ3JGXM61ail1pp716pUAAQA/1WqAAAAAAgwHmMAAAAGAAAAAQEABwA+AAw2AAAiAAvKQw0fWfgw6nQE4MTsGY7tTwepogu1YED+3ZSs+rkBbgAiAAvZHMHbKCiUnL7jxkTMqhbMNtoyKqi7eg5Tm7eQFQM3+jCCARQGCFUEgQUDAikBBIIBBgAUAAsBADiGza+SuXvKAkfBWbYLXXmneXfAUaUtynArnhey7icOvBNqNVVROXx9iaH5wxgmzshJRDXIkJhYpZ8xfNkFqfPkAtHSw3IugrTe4bokzVwVMe+a0c+OT9ptDEkb7TiUKNc0hX2O0jc4dPSzYBdAn/3HSnV1f5DQBKT/QTk/Io+7F0Vu2phz96Ax7d73mjufehE920hq77v/mVXNOtmyQ6Q9OXQCgDwgfAQwBc6iuBLsXPAK1GUN2D/8N29+CQQfa0/KzHrHc/Ioh+PTOgg7TaYmJhB+NasdzV7t3YlAa0x6ZPPZwagpSnbrGpnIw2H0Wvy/YebfvGskymvvsiSwUGQwDgYIVQSBBQMCKQIEAgAAMA0GCSqGSIb3DQEBCwUAA4IBAQBh6LiD+zec5Tp0qZnpNniw519/JHOVN3HDcF1mv/BKSEeu7BmWp62c3Agf6+8anWsrpTg936DAgCKUgjJN2+m5fdJhNOUs662/PlLE17FjeAYMIxfNlHlP5nNRq5F6T8I1BDaCsT4dgmQlqUkCrHRaPB9nqajPOjYihYpSxNnUT/b4NFnK8T7gEvrfGM1EF6m1dPx4IQSxznBD4XwjBU/KjjVEuPFks/bPwf/sz5t3itnpJTFazrnBp4Wr2kzxKLoPDKmhtgStE0mArpLWnEbgMXGmkm5mgzHCFs5phEghhkAHfyT/lLjMKzzkN7BmjL6qM9TIA67g8LIMuI/wyKXe-----END CERTIFICATE-----"
	goodString2 := "tNPEL9e3O97nQ2nTlzwyPxxNLAjwwSvTnGcVeOmIfbboqBZkixDx3TR6/n13s7eury6LVqOjEOsItExy/BvXE+g6WTP61dEnenM1fNlmNY/O6bNqEwgxVEfamdNBN9FYuB2inzwueEiB5J2WtkCB+0c2pr86oMl8eYlUve1r0+VRbOhQVhMKskVLKZonBxvLrup1geqIDD8DuK/EVt8aCYfjY5n0B1NtfSwQpNzWjmTc0g9H0aH/tYerfB6Q+KqVo2be1wWQscNBfVvVGjwB3brT6k2ODUSCDlGJV5IhVNq+ooM5s+o21c8+fX1bXiFOdA7T/TnuCKJyEMxrAvzypQ=="

	err := ValidatePemEncodedKey(goodString1)
	assert.NoError(t, err)

	err = ValidatePemEncodedKey(goodString2)
	assert.NoError(t, err)

	badString1 := "fishy_symbols \" ` ' )))((*&^ "
	badString2 := "\" \" \" SELECT * FROM TABLE"
	badString3 := "<inputTag>"

	err = ValidatePemEncodedKey(badString1)
	assert.Error(t, err)

	err = ValidatePemEncodedKey(badString2)
	assert.Error(t, err)

	err = ValidatePemEncodedKey(badString3)
	assert.Error(t, err)
}

func TestValidateUUIDv4(t *testing.T) {

	goodUUID := "2a16f0bd-aa32-458d-9d7b-fe1a7048c3e2"
	err := ValidateUUIDv4(goodUUID)
	assert.NoError(t, err)

	badUUID1 := "sample-string-with-novalidValue"
	badUUID2 := "$%^&#$--1234-7890-2345"
	badUUID3 := "fChs4vXGYJ6hUHCILkLNg1STbF3YC270tVb3pUP9AfA="

	err = ValidateUUIDv4(badUUID1)
	assert.Error(t, err)

	err = ValidateUUIDv4(badUUID2)
	assert.Error(t, err)

	err = ValidateUUIDv4(badUUID3)
	assert.Error(t, err)
}

func TestValidateBase64String(t *testing.T) {

	goodUUID := "fChs4vXGYJ6hUHCILkLNg1STbF3YC270tVb3pUP9AfA="
	err := ValidateBase64String(goodUUID)
	assert.NoError(t, err)

	badUUID1 := "sample-string-with-novalidValue"
	badUUID2 := "$%^&#$--1234-7890-2345"
	badUUID3 := "2a16f0bd-aa32-458d-9d7b-fe1a7048c3e2"

	err = ValidateBase64String(badUUID1)
	assert.Error(t, err)

	err = ValidateBase64String(badUUID2)
	assert.Error(t, err)

	err = ValidateBase64String(badUUID3)
	assert.Error(t, err)
}

func TestValidateHexString(t *testing.T) {

	goodUUID := "f41d0ebcaafb14a3a9a16329bd4c1248db2759576e1e8992c342f6cb52bab333"
	err := ValidateHexString(goodUUID)
	assert.NoError(t, err)

	badUUID1 := "sample-string-with-novalidValue"
	badUUID2 := "$%^&#$--1234-7890-2345"
	badUUID3 := "2a16f0bd-aa32-458d-9d7b-fe1a7048c3e2"

	err = ValidateHexString(badUUID1)
	assert.Error(t, err)

	err = ValidateHexString(badUUID2)
	assert.Error(t, err)

	err = ValidateHexString(badUUID3)
	assert.Error(t, err)
}

func TestValidateXMLString(t *testing.T) {

	xmlFile1, _ := ioutil.ReadFile("../test/domXML.xml")
	goodXML1 := string(xmlFile1)

	err := ValidateXMLString(goodXML1)
	assert.NoError(t, err)

	xmlFile2, _ := ioutil.ReadFile("../test/samlCert.xml")
	goodXML2 := string(xmlFile2)

	err = ValidateXMLString(goodXML2)
	assert.NoError(t, err)

	badXML := "$%^&#$--1234-7890-2345"
	err = ValidateXMLString(badXML)
	assert.Error(t, err)
}

func TestBlankString(t *testing.T) {
	assert := assert.New(t)
	testXML := ""
	fmt.Printf("Test XML: %s\n", testXML)
	isValidXML := ValidateXMLString(testXML)
	assert.Error(isValidXML, "Validation Failure: This is not good XML")

}

func TestNewPlainString(t *testing.T) {
	assert := assert.New(t)
	testXML := "This is definitely not XML"
	fmt.Printf("Test XML: %s\n", testXML)
	isValidXML := ValidateXMLString(testXML)
	assert.Error(isValidXML, "Validation Failure: This is not good XML")

}

func TestValidXML(t *testing.T) {
	assert := assert.New(t)
	testXML := `
<?xml version="1.0" encoding="UTF-8"?>
<CATALOG>
  <CD>
    <TITLE>Red</TITLE>
    <ARTIST>The Communards</ARTIST>
    <COUNTRY>UK</COUNTRY>
    <COMPANY>London</COMPANY>
    <PRICE>7.80</PRICE>
    <YEAR>1987</YEAR>
  </CD>
  <CD>
    <TITLE>Unchain my heart</TITLE>
    <ARTIST>Joe Cocker</ARTIST>
    <COUNTRY>USA</COUNTRY>
    <COMPANY>EMI</COMPANY>
    <PRICE>8.20</PRICE>
    <YEAR>1987</YEAR>
  </CD>
</CATALOG>
`
	fmt.Printf("Test XML: %s\n", testXML)
	assert.NoError(ValidateXMLString(testXML), "Validation Failure: This is good XML")
}

func TestNewInvalidXML(t *testing.T) {
	assert := assert.New(t)
	testXML := `
<?xml version="1.0" encoding="UTF-8"?>
<CATALOG>
  <CDdddddddd>
    <TITLE>Red</TITLE>
    <ARTIST>The Communards</ARTIST>
    <COUNTRY>UK</COUNTRY>
    <COMPANY>London</COMPANY>
    <PRICE>7.80</PRICE>
    <YEAR>1987</YEAR>
  </CD>
  </CD>
    <TITLE>Unchain my heart</TITLE>
    <ARTIST>Joe Cocker</ARTIST>
    <COUNTRY>USA</COUNTRY>
    <COMPANY>EMI</COMPANY>
    <PRICE>8.20</PRICE>
    <YEAR>1987</YEAR>
  </CD>
</CATALOG>
`
	fmt.Printf("Test XML: %s\n", testXML)
	assert.Error(ValidateXMLString(testXML), "Validation Failure: This is bad XML!")
}

func TestNewSAML(t *testing.T) {
	testXML := `<?xml version="1.0" encoding="UTF-8"?>
<saml2:Assertion ID="MapAssertion" IssueInstant="2019-08-13T20:35:04.312Z" Version="2.0" 
    xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
    <saml2:Issuer>https://vs.server.com:8443</saml2:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>
            <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <Reference URI="#MapAssertion">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <DigestValue>nm/o1HX2yhqYwcAVfKYELusc8UdMXOP36XmM+QzjaTo=</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>FQx+EN6sbjgTPYppa4zXFuerAFaXMrGjiEx7VUm1FBgRWs4eTTDw+hnMUIGy5maGZhuJMxTHCRPM
VnTsAFgSJwrsbT4xVqdR0Pia1GCbQ9pwwO9rubFcXkmbeoSqlZKGlgw0itC4sx/jfJSPRMwcXeEA
U/ikNufVcWfUhPE2+icmpy0NgVz8+WybVs+UDj22sMatD9u3E2rCziuDu3heKvOUfHhIKohoXEBz
Y6aWQ1Q6XMnh9YqBBpV/q+YHUDDABnRGZhrt1+YR4gaXppOKvRYen/VfLa1khaDJOzBPiBlSxzEa
fngWTFj+rq1nJf+IhWFaMacVB2wB3wE7puN2/5M11GT6p0Cy5P1mAKLA/Hf65EtejpyiGFP3YbQl
8hzFlfycLVDtyiwd1khSmVRieYf3Qz0nVcO8oAQMc2w3OtmPRvnFvYKwFaHR80j5Y2DRsWVbqnLF
guGouSQRVoa8UoGl+9jeYZGwE9LpqyHTJbT5yDOCETaBQvdUFRPmVSuI</SignatureValue>
        <KeyInfo>
            <X509Data>
                <X509Certificate>MIIEYzCCAsugAwIBAgIET0rGXTANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzELMAkGA1UE CBMCQ0ExDzANBgNVBAcTBkZvbHNvbTEOMAwGA1UEChMFSW50ZWwxEjAQBgNVBAsTCU10IFdpbHNv bjERMA8GA1UEAxMIbXR3aWxzb24wHhcNMTkwODA3MTY0OTU4WhcNMjkwODA0MTY0OTU4WjBiMQsw CQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExDzANBgNVBAcTBkZvbHNvbTEOMAwGA1UEChMFSW50ZWwx EjAQBgNVBAsTCU10IFdpbHNvbjERMA8GA1UEAxMIbXR3aWxzb24wggGiMA0GCSqGSIb3DQEBAQUA A4IBjwAwggGKAoIBgQCGD6Wfd4s3bC46uhrVl0hLd/OqpLaAac59mldriEPAHgw8G0DEZaewjVFp ZQoBSELiNQCPp7HVV+0MIsPrIj5Dw6zMNESbDTuRqRQQM9j2D+F47Z61ngeLFjY0Ht/LQvaj1TPq sT6A1Xb624PaD/7yNz78cbrm4rkaaf7ROm1LhUDG1Fd7PAgaAvgxBBHVK+pPLAuTASX288CJ/19c uTv5Odu2V+HXI6lJZpbYxbY+o9cAO872shrBQEJJDa8IMXVHKi9L9xgQSRECiSB2NSb53PExOMuB g5xWA+F8Vic2REcAxvhE+1uvQRCGY/ZBuH6FcmFohjWgafmu8zJqSdL5STIArwYHF12ERhbwF15X H60hbyLBm7WGpSzWkphamFN3mn/qm41+WRA/Vp5uRU5ifeIovHt1lgXgPc6sk5a9H2pFeU/tyunq qgFHHNC1k45Oa5bL8HMBq8j6CfzNbPoPd0bvgXRYpa3dS54NuJctPcHiOmtCqwOSVVxwayJGfqUC AwEAAaMhMB8wHQYDVR0OBBYEFLIGahyJ3x/utXbtVqlolgB8huu9MA0GCSqGSIb3DQEBCwUAA4IB gQAHgktGAWGxj5aGOgxWk7GK9OcEgmmBJRiNfVjsjFwDCAyCP3gFNVDwg67OxbBIo77V5ikey76e lYRbYzsRUWLJ54QnwbPt42aOYTNuDgs97s8H+vEwlBj016cvo0HhslJn2X7EK9eYweZzBZ82KUpC YKhMGyeS6iAAd39iBakqjY0khpJlX+Ti6ITV4ZDilXrK2FWYUvl0ZU2ytaoh8r/s1pJa17VKDgNJ btMvbXae5EYoyVwr/DoYroPTvS01MHOoRmwOxGjRlr4cnTfXmEEZiZuGrvQcyPySdadZK0QHokL0 snXKg0u4YIU60oaTYn0jiQmCn4YACJWScBS9Mm/pO4urXkqj71VqJsHVZxRyUm1Bss+MaCn7JhlY BIsHDnaml3ZyX+KLnv/eTQYsaXeaUk0APdId3nQqiMuFqpZjRdOZrE2Kn7IES2DI/wbnbxnRcLLO AvUXoxs/yIf0UxEMbR77+Z3hHn4YbM3s1Uu2ZqCQmHIhWK1NsD8gYNsuLl8=</X509Certificate>
            </X509Data>
        </KeyInfo>
    </Signature>
    <saml2:Subject>
        <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">O23RU15</saml2:NameID>
        <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">Intel Security Libraries</saml2:NameID>
            <saml2:SubjectConfirmationData NotBefore="2019-08-13T20:35:04.312Z" NotOnOrAfter="2019-08-14T20:35:04.312Z"/>
        </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:AttributeStatement>
        <saml2:Attribute Name="biosVersion">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">SE5C620.86B.0X.01.0155.073020181001</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="hostName">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">O23RU15</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="tpmVersion">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">2.0</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="processorInfo">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">54 06 05 00 FF FB EB BF</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="vmmName">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">QEMU</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="hardwareUuid">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">00964993-89C1-E711-906E-00163566263E</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="errorCode">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">0</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="vmmVersion">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">2.10.0</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="osName">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">RedHatEnterpriseServer</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="noOfSockets">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">2</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="tpmEnabled">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="biosName">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">Intel Corporation</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="osVersion">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">7.6</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="processorFlags">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush dts acpi mmx fxsr sse sse2 ss ht tm pbe syscall nx pdpe1gb rdtscp lm constant_tsc art arch_perfmon pebs bts rep_good nopl xtopology nonstop_tsc aperfmperf eagerfpu pni pclmulqdq dtes64 monitor ds_cpl vmx smx est tm2 ssse3 sdbg fma cx16 xtpr pdcm pcid dca sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand lahf_lm abm 3dnowprefetch epb cat_l3 cdp_l3 intel_ppin intel_pt ssbd mba ibrs ibpb stibp tpr_shadow vnmi flexpriority ept vpid fsgsbase tsc_adjust bmi1 hle avx2 smep bmi2 erms invpcid rtm cqm mpx rdt_a avx512f avx512dq rdseed adx smap clflushopt clwb avx512cd avx512bw avx512vl xsaveopt xsavec xgetbv1 cqm_llc cqm_occup_llc cqm_mbm_total cqm_mbm_local dtherm ida arat pln pts hwp hwp_act_window hwp_epp hwp_pkg_req pku ospke spec_ctrl intel_stibp flush_l1d</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="installedComponents">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">[wlagent, tagent]</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="tbootInstalled">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="txtEnabled">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="pcrBanks">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">[SHA1, SHA256]</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="isDockerEnv">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">false</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="FEATURE_TPM">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="FEATURE_TXT">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_PLATFORM">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_OS">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_HOST_UNIQUE">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_ASSET_TAG">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">NA</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_SOFTWARE">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="TRUST_OVERALL">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">true</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="Binding_Key_Certificate">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">-----BEGIN CERTIFICATE-----&#xd;
MIIFITCCA4mgAwIBAgIJANyKbWsRVtYiMA0GCSqGSIb3DQEBDAUAMBsxGTAXBgNVBAMTEG10d2ls&#xd;
c29uLXBjYS1haWswHhcNMTkwODA3MTcyMzE2WhcNMjkwODA0MTcyMzE2WjAlMSMwIQYDVQQDDBpD&#xd;
Tj1CaW5kaW5nX0tleV9DZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB&#xd;
AJrShQOtV3jknK5vYJNO8HqenzlaKQ26QMoT8McDPbvoNjVxRMQ5/RiDmuGNlnzRez6TMht3kkMu&#xd;
a6aLx4jYDoas8m/AheMFflCQK4jvKqP5UqoGZyHLlVh+v+oHi+gonNkFCYQ8whm6ckxt1XqxyQCV&#xd;
y/KDTNITJZOdwMvMkY5c0OjXRnbXoXi3iODMCVVQO979un6ogBmtnYVr/cIjjZRhJo6DkB16OBzy&#xd;
bDa47noj1H8LeRMttCZVxow39fx+8wcfLcjxcQP8HiY9M9aoK4jPeWN/4KzWAbbEbcaO17t1GrbC&#xd;
JG6W6RQCAsqcE3dLsuDGNTJ/TExmWpyek6yoR6MCAwEAAaOCAdwwggHYMA4GA1UdDwEB/wQEAwIF&#xd;
IDCBnQYHVQSBBQMCKQSBkf9UQ0eAFwAiAAtuQF7sjD4U0B5+h9U5/40rsQtC3IqGsWag4rXk471G&#xd;
zgAEAP9VqgAAAAAAFE6sAAAABQAAAAABAAcAKAAIMgAAIgALpg1+mlPAzBTW+rW2c4JgrvvIVhfv&#xd;
QpNMa09ob+flDY4AIgAL8Q5CCTUFUaLaGV1+JCzkWLhIh+gZIRH/fZ10rnf93dIwggEUBghVBIEF&#xd;
AwIpAQSCAQYAFAALAQB2+KW776Be8GYZIsO3UuRRXvs3I87bJngO0GXOj9EnTISmLJdcIeAlkkKR&#xd;
LvCuDLLlFh1QTDY6lQhaRcT4Q6lRoCM7k4fsGadLXGjT8U85tjNmGGicpAL5vKXeQUhzNVHrjCiq&#xd;
mN5hs5o4YDCDRlzjz6Pc9wqBEUFiyOjg60hnNgFS4s/INFK+rEgoPdVDNz7/dZiR4hNiD/m89ZyS&#xd;
wUFwUoZqTQdBjFfpVDRkBYN1hUUmMQVEFC6xolHgU3CmvwB3NMmoig41BoUv6d8UjmaZsnaer7WZ&#xd;
XJ/sTwLMfhrMgrj/Xp76lfr7VJFB09qaONdKUu1/4wf7I/1hQbmZn0DVMA4GCFUEgQUDAikCBAIA&#xd;
ADANBgkqhkiG9w0BAQwFAAOCAYEAQVSDj4B+4K4+SCjcR4C31jvxh5MqgBsUcZjB3UYayLr59/NQ&#xd;
1SuWwpntYIGqzcGWN8UssqQh8i5cU+mtnf5qNCpDK0FtZeWuSvTok4eOrPxT/jahQnFsYuArNgHJ&#xd;
2HNxanAMWcshCJ4wugEErSo5FiLSFEC4jE16BzDFwXpHfVpocbJTBuHiKu2r1ZWHzaOU5TIsaZn3&#xd;
N2EK7Sqj7rIy0Xi3/lwlFurs3rZOynnsns1yZgMELMVJyP6T+yqUkNSzWGdRki9kOOAh9xVZna/Z&#xd;
Kdztuma5tfljWa5sUnux61J0FinVlQfyDCJYMIT3XQr2Q1s54yxMyrFGVeMJKKh5Ixr6dUEVmF2/&#xd;
rVg9vNuLpHJCkubs32+YMNePLuif/wfoO1zAJuC0vmWCfB2ipjoytJvWdhMxxe5lpIZgT9L1ny53&#xd;
0pHbuDQRICFbUm8DOgnD/NcpCuLy24GJzI7RFDNnqsyJ1rtlUXeja2lzI0b/ZJnISR3S/JZlmxuh&#xd;
2BUWmgMd&#xd;
-----END CERTIFICATE-----</saml2:AttributeValue>
        </saml2:Attribute>
        <saml2:Attribute Name="AIK_Certificate">
            <saml2:AttributeValue xmlns:xsd="http://www.w3.org/2001/XMLSchema" 
                xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xsd:string">-----BEGIN CERTIFICATE-----&#xd; MIIDTjCCAbagAwIBAgIGAWxtGvaGMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAMTEG10d2lsc29u&#xd; LXBjYS1haWswHhcNMTkwODA3MTcyMjU5WhcNMjkwODA2MTcyMjU5WjAAMIIBIjANBgkqhkiG9w0B&#xd; AQEFAAOCAQ8AMIIBCgKCAQEAnhh03DnQYS86N904/QA2VifuavSn3x+uwX1undxzFsp0DqgyjsNc&#xd; Bjt6+Yr9W3bmgEl1nun2ehhA5Q7AO7Jo5mompyn06OucTRvMTssTMwpcNyjfozCHejMK0aG7LVPr&#xd; 7Fk4KDE6ArSSeno/8QPbhW7eueHXJCsQ7rwDWet+sfaBCDRVtbVH5rrzqf2Jw3ekLBkISUuU+xd2&#xd; 0qZsAe/VBlFTFM5vf091OwOiGulpfJhU7d/UYkiiJY0rmG7jF6IZjvsUAWYfwiPdLtXabQI/xaTR&#xd; ekPdTBwFQoC7WMClK7JBwKae1EKyY3VDq63CChUCsgye/y6p/3EaI2NxBgBtpwIDAQABozMwMTAv&#xd; BgNVHREBAf8EJTAjgSEAC/0ANf39A/39VV0cYv39/TH9/V39/f39Ef1JWP0TcP0wDQYJKoZIhvcN&#xd; AQELBQADggGBACNYVC5JT1G2eSxs1Td5yoO4vuIACyqBVYrijDrgr7isRuJmYvimn8vtZEhk4MNP&#xd; jRuZTc0JannDKcySwaeUbN7d17iraDMStmi1i0cIPP5YhXNFszgp4QplFXoyfg5REpjsYV7kTxRo&#xd; AO6fuC2B+5h2kPi+uZwKnvXxgEX6zeX4Qr3h/kFYw1EbDgdHmPQLcs02BMRF8UPFoZAe8wusrTJM&#xd; c/IP+j1mW8h2rAm3YlN+dWkMdU2vtEXuve3zHC1ndRTFEOhAHXfwXM5nRl8nopqPsdP4scEagjZR&#xd; FleODT5JA7QpIwhnnNYTiorghKtK+jNGjrtFE0jXmQWTNDD5IjQ3JJ5luPlpzmM7TzKLMPyl2PcG&#xd; xnjVLebDuZe12aByG0+jgmbHJOe0wVGt2ezajd+zgxXZlgNm/isR/xJd0lNyWnxb+o6ZtqE4TA13&#xd; 5ihJR+qraQT24Vpb9AffL+s3GWDH255YGVEa2+X8q21Uayt5+nasYRL9BK20UI4NCcpEBQ==&#xd;
-----END CERTIFICATE-----</saml2:AttributeValue>
        </saml2:Attribute>
    </saml2:AttributeStatement>
</saml2:Assertion>`
	fmt.Printf("Test XML: %s\n", testXML)
	assert.NoError(t, ValidateXMLString(testXML), "Validation Failure: This is good XML!")
}

func TestValidateDate(t *testing.T) {

	goodDate1 := "2006-12-13T15:04:05"

	err := ValidateDate(goodDate1)
	assert.NoError(t, err)

	badDate1 := "1/13/2010"
	badDate2 := "29-02-200a"
	badDate3 := "2006-12-13"

	err = ValidateDate(badDate1)
	assert.Error(t, err)

	err = ValidateDate(badDate2)
	assert.Error(t, err)

	err = ValidateDate(badDate3)
	assert.Error(t, err)
}

func TestValidateK8sJWT(t *testing.T) {

	goodJwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRlZmF1bHQtdG9rZW4tbnZtNmIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoiZGVmYXVsdCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjdhNWFiNzIzLTA0NWUtNGFkOS04MmM4LTIzY2ExYzM2YTAzOSIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.MV6ikR6OiYGdZ8lGuVlIzIQemxHrEX42ECewD5T-RCUgYD3iezElWQkRt_4kElIKex7vaxie3kReFbPp1uGctC5proRytLpHrNtoPR3yVqROGtfBNN1rO_fVh0uOUEk83Fj7LqhmTTT1pRFVqLc9IHcaPAwus4qRX8tbl7nWiWM896KqVMo2NJklfCTtsmkbaCpv6Q6333wJr7imUWegmNpC2uV9otgBOiaCJMUAH5A75dkRRup8fT8Jhzyk4aC-kWUjBVurRkxRkBHReh6ZA-cHMvs6-d3Z8q7c8id0X99bXvY76d3lO2uxcVOpOu1505cmcvD3HK6pTqhrOdV9LQ"

	err := ValidateJWT(goodJwt)
	assert.NoError(t, err)

	badJwt1 := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ.."
	err = ValidateJWT(badJwt1)
	assert.Error(t, err)

	badJwt2 := "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik9RZFFsME11UVdfUnBhWDZfZG1BVTIzdkI1cHNETVBsNlFoYUhhQURObmsifQ."
	err = ValidateJWT(badJwt2)
	assert.Error(t, err)

}

func TestValidateAccount(t *testing.T) {
	type args struct {
		uname string
		pwd   string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Valid username and password",
			args: args{
				uname: "username",
				pwd:   "P@ssw0rd",
			},
			wantErr: false,
		},
		{
			name: "Invalid username and password",
			args: args{
				uname: "username(_)",
				pwd:   "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAccount(tt.args.uname, tt.args.pwd); (err != nil) != tt.wantErr {
				t.Errorf("ValidateAccount() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateNameString(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate name string for valid username",
			args: args{
				name: "username",
			},
			wantErr: false,
		},
		{
			name: "Validate name string for invalid username",
			args: args{
				name: "username()",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateNameString(tt.args.name); (err != nil) != tt.wantErr {
				t.Errorf("ValidateNameString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateUserNameString(t *testing.T) {
	type args struct {
		uname string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidateUserNameString with valid username",
			args: args{
				uname: "username",
			},
			wantErr: false,
		},
		{
			name: "ValidateUserNameString with invalid username",
			args: args{
				uname: "username()",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateUserNameString(tt.args.uname); (err != nil) != tt.wantErr {
				t.Errorf("ValidateUserNameString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateEmailString(t *testing.T) {
	type args struct {
		email string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidateEmailString with valid email",
			args: args{
				email: "username@mail.com",
			},
			wantErr: false,
		},
		{
			name: "ValidateEmailString with invalid email",
			args: args{
				email: "username()@mail.com",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateEmailString(tt.args.email); (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmailString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePasswordString(t *testing.T) {
	type args struct {
		pwd string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate PasswordString with valid password",
			args: args{
				pwd: "P@ssw0rd",
			},
			wantErr: false,
		},
		{
			name: "Validate PasswordString with invalid password",
			args: args{
				pwd: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePasswordString(tt.args.pwd); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePasswordString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateTextString(t *testing.T) {
	type args struct {
		text string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate TextString with valid text",
			args: args{
				text: "Text",
			},
			wantErr: false,
		},
		{
			name: "Validate TextString with invalid text",
			args: args{
				text: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateTextString(tt.args.text); (err != nil) != tt.wantErr {
				t.Errorf("ValidateTextString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHostname(t *testing.T) {
	type args struct {
		hostname string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate Hostname with valid hostname",
			args: args{
				hostname: "Hostname",
			},
			wantErr: false,
		},
		{
			name: "Validate Hostname with invalid hostname",
			args: args{
				hostname: "Hostname()",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHostname(tt.args.hostname); (err != nil) != tt.wantErr {
				t.Errorf("ValidateHostname() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	type args struct {
		port string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate valid Port",
			args: args{
				port: "9443",
			},
			wantErr: false,
		},
		{
			name: "Validate invalid port",
			args: args{
				port: "@!%",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePort(tt.args.port); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIdentifier(t *testing.T) {
	type args struct {
		idf string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate indentifier with valid user id",
			args: args{
				idf: "userid",
			},
			wantErr: false,
		},
		{
			name: "Validate indentifier with invalid user id",
			args: args{
				idf: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIdentifier(tt.args.idf); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIdentifier() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateIssuer(t *testing.T) {
	type args struct {
		isf string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate issuer with valid issuer",
			args: args{
				isf: "Intel",
			},
			wantErr: false,
		},
		{
			name: "Validate issuer with invalid issuer",
			args: args{
				isf: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateIssuer(tt.args.isf); (err != nil) != tt.wantErr {
				t.Errorf("ValidateIssuer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSha256HexString(t *testing.T) {
	type args struct {
		value string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate sha256 hex string with valid sha256",
			args: args{
				value: "9707b390c263356173cdd4a812c926ed85e1fd611671096f19230ffbbc4629dc",
			},
			wantErr: false,
		},
		{
			name: "Validate sha256 hex string with invalid sha256",
			args: args{
				value: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSha256HexString(tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSha256HexString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateSha384HexString(t *testing.T) {
	type args struct {
		value string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate sha384 hex string with valid sha384",
			args: args{
				value: "e8e4d9727695438c7f5c91347e50e3d68eaab5fe3f856685de5a80fbaafb3c1700776dea0eb7db09c940466ba270a4e4",
			},
			wantErr: false,
		},
		{
			name: "Validate sha384 hex string with invalid sha384",
			args: args{
				value: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateSha384HexString(tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("ValidateSha384HexString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHardwareUUID(t *testing.T) {
	type args struct {
		uuid string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate uuid with valid uuid",
			args: args{
				uuid: "68f460ea-36e3-4f21-9e38-b11ad454b8a5",
			},
			wantErr: false,
		},
		{
			name: "Validate uuid with invalid uuid",
			args: args{
				uuid: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateHardwareUUID(tt.args.uuid); (err != nil) != tt.wantErr {
				t.Errorf("ValidateHardwareUUID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateConnectionString(t *testing.T) {
	type args struct {
		cs string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Validate connection string with valid connection string",
			args: args{
				cs: "https://127.0.0.1:9443/v1/hvs",
			},
			wantErr: false,
		},
		{
			name: "Validate connection string with invalid connection string",
			args: args{
				cs: "%$#",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateConnectionString(tt.args.cs); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConnectionString() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPagination(t *testing.T) {
	limit, afterid, err := ValidatePaginationValues("5", "6")
	if !(limit == 5 && afterid == 6 && err == nil) {
		t.Errorf("Error validating values")
	}
	_, _, err = ValidatePaginationValues("-5", "6")
	if err == nil {
		t.Errorf("Error validating values")
	}
	_, _, err = ValidatePaginationValues("5", "aaaa")
	if err == nil {
		t.Errorf("Error validating values")
	}
}
