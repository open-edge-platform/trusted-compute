#!/bin/sh
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

export WAIT_INTERVAL=${WAIT_INTERVAL:-2}
export ITERATIONS=${ITERATIONS:-100}
i=0

# Waits for $ITERATIONS * $WAIT_INTERVAL for any service with given API with $URL
while [[ $i -lt $ITERATIONS ]]; do
  resp=$(curl -k -sw '%{http_code}' --connect-timeout 1 "$URL" -o /dev/null)
  if [[ $resp -eq 200 ]]; then
    version_resp=$(curl -k "$URL")
    echo "version_resp" "$version_resp"
    version=$(echo $version_resp | grep -o 'Version: [0-9.]*' | cut -d' ' -f2)
    echo "Version" $version
    echo "VERSION" $VERSION
    VERSION=${VERSION%%-*}
    if [[ "$version" == "$VERSION" ]]; then
      echo "$DEPEDENT_SERVICE_NAME $version is running"
      exit 0
    fi
  fi
  sleep $WAIT_INTERVAL
  i=$((i + 1))
  echo "Waiting for $DEPEDENT_SERVICE_NAME connection, attempt: $i"
done
if [ $i -eq $ITERATIONS ]; then
  echo "Error: timeout exceeded for job/container: $COMPONENT"
  exit 1
fi
