<!---
  SPDX-FileCopyrightText: (C) 2025 Intel Corporation
  SPDX-License-Identifier: BSD-3-Clause
-->

# Sample Trusted Compute curl Service (curl-loop)

This sample runs the curl service within a Trusted Compute environment. curl-loop is a well-known application to issue an HTTP request that can be used to experiment with egress traffic from edge cluster.

## External Networking in EMF 
In a Kubernetes cluster, pods are isolated from the external network by default, preventing them from initiating connections to external services. To enable pods to access external services, Kubernetes offers a feature called Egress Network Policy. This feature allows you to define rules specifying which external endpoints pods are permitted to access.

## Pre-work
The EMF cluster deploys Calico as pre-configured CNI available in the [EMF Cluster template](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/additional_howtos/set_up_a_cluster_template.html), which sets the network rules for the cluster, and by default, global rules do not permit egress traffic. Therefore, a network policy is needed to allow egress traffic. In the sample application, we provide a reference [network policy](helm/templates/network.yaml) that permits all egress traffic. Users can customize the network policy according to their specific requirements.

## Deployment of sample curl service

In the repository, we have sample curl service Helm charts and EMF deployment packages. The Helm charts need to be packaged and uploaded to the registry. The instructions below detail this process.

This Helm chart deploys a container using `curlimages/curl` that continuously curls http://httpbin.org/headers every 5 seconds using the following configuration:


To use the chart package it and upload it to your local OCI registry:

```bash
helm package helm
```

Upload the package to your local OCI registry following the instructions
[here](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/package_software/push_registry.html)

### Deployment Package

The deployment package is designed to be used on Edge Manageability Framework.
