#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


while getopts :d:n::s:u:t:h opt; do
  case "$opt" in
  u) CMS_URL="${OPTARG}" ;;
  n) CERT_CN="${OPTARG}" ;;
  s) SAN_LIST="${OPTARG}" ;;
  d) CERTS_DIR="${OPTARG}" ;;
  t) BEARER_TOKEN="${OPTARG}" ;;
  h) echo 'Usage: $0 [-d /working/directory] [-n CommonName] -s "hostname1.mydomain.net,hostname2,hostname3.yourdomain.com" -u "CMS URL" -t "BEARER_TOKEN' ; exit ;;
  esac
done

if [ -z "$CERT_CN" ]; then
  echo "Error: missing cert common name. Aborting..."
  exit 1
fi

if [ -z "$SAN_LIST" ]; then
  echo "Error: Subject Alternative Names for the cert have not been provided. Aborting..."
  exit 1
fi

if [ -z "$CMS_URL" ]; then
  echo "Error: CMS_UR has not been provided. Aborting..."
  exit 1
fi

if [ -z "$BEARER_TOKEN" ]; then
  echo "Error: BEARER_TOKEN has not been provided. Aborting..."
  exit 1
fi

if [ ! -w $CERTS_DIR ]; then
  echo "Error: No write permissions for workdir. Aborting..."
  exit 1
fi

cd $CERTS_DIR

echo "Creating certificate request..."

cat >csr.json <<EOF
{
  "hosts": [
	$(echo $SAN_LIST | tr -s "[:space:]" | sed 's/,/\",\"/g' | sed 's/^/\"/' | sed 's/$/\"/' | sed 's/,/,\n/g')
  ],
  "CN": "$CERT_CN",
  "key": {
	"algo": "rsa",
	"size": 3072
  }
}
EOF

CSR_FILE=sslcert
cfssl genkey csr.json | cfssljson -bare $CSR_FILE

if [ $? -ne 0 ]; then
  echo "Error generating CSR. Aborting..."
  exit 1
fi

echo "Downloading TLS Cert from CMS...."
curl --noproxy "*" -k -X POST ${CMS_URL}/certificates?certType=TLS -H 'Accept: application/x-pem-file' -H "Authorization: Bearer $BEARER_TOKEN" -H 'Content-Type: application/x-pem-file' --data-binary "@$CSR_FILE.csr" > server.pem
