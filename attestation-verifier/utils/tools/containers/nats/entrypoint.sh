#!/bin/bash
# SPDX-FileCopyrightText: 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause


sh download-tls-certs.sh -d secrets -n "$NATS_CERT_COMMON_NAME" -u "$CMS_K8S_ENDPOINT_URL" -s "$NATS_CERT_SAN_LIST" -t $BEARER_TOKEN
if [ $? != 0 ]; then
    echo "Error while downloading tls certs for nats server"
    exit 1
fi

aas_pod=$(./kubectl get pod -n $NAMESPACE -l app.kubernetes.io/name=aas -o jsonpath="{.items[0].metadata.name}")
if [ $? != 0 ]; then
    echo "Error while retrieving AAS pod name"
    exit 1
fi
credentials=$(./kubectl exec -n $NAMESPACE --stdin $aas_pod -- authservice setup create-credentials --force)
if [ $? != 0 ]; then
    echo "Error while executing create-credentials setup task"
    exit 1
fi
nats_operator=$(echo "$credentials" | grep operator: | awk '{print $2}')
if [ $? != 0 ]; then
    echo "Failed to retrieve nats operator from create-credentials output"
    exit 1
fi
resolver_preload=$(echo "$credentials" | grep "Account $NATS_ACCOUNT_NAME" -A 1)
if [ $? != 0 ]; then
    echo "Failed to retrieve resolver preload from create-credentials output"
    exit 1
fi
resolver_jwt=$(echo "$resolver_preload" | cut -d$'\n' -f2)
if [ $? != 0 ]; then
    echo "Failed to retrieve resolver jwt from create-credentials output"
    exit 1
fi
sed -i "s#operator:.*#operator: $nats_operator#g" nats.conf || exit 1
sed -i "s#resolver_preload:.*#resolver_preload: { $resolver_jwt }#g" nats.conf || exit 1

./kubectl create configmap nats-config --from-file=nats.conf --namespace=$NAMESPACE
if [ $? != 0 ]; then
    echo "Failed to create NATS configmap"
    exit 1
fi
./kubectl create secret generic nats-certs --from-file=secrets --namespace=$NAMESPACE
if [ $? != 0 ]; then
    echo "Failed to create NATS certificates"
    exit 1
fi
