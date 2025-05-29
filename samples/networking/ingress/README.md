<!---
  SPDX-FileCopyrightText: (C) 2025 Intel Corporation
  SPDX-License-Identifier: Apache-2.0
-->

# Sample Trusted Compute HTTP Server Service (httpbin)

This sample runs the Httpbin service within a Trusted Compute environment. Httpbin is a well-known HTTP testing service that can be used to experiment with ingress traffic into edge cluster.

## External Networking in EMF 

The Kubernetes network model utilizes the Service object for applications and offers multiple methods to expose the Service to an external IP address. EMF provides a Load Balancer package that includes MetalLB, a load balancer for bare-metal Kubernetes clusters, which assigns External IP addresses to services (type=LoadBalancer) for external workload exposure.

## Deployment of sample ingress httpbin service
Before deploying the httpbin service, it is necessary to deploy the EMF [Load Balancer package](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/package_software/extensions/load_balancer.html) on the cluster. The deployment workflow involves several configuration parameters for MetalLB, with the most basic configuration requiring the IP address of the Edge Node to be set in the staticIPs field.

```bash
helm package helm
```

Upload the package to your local OCI registry following the instructions
[here](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/package_software/push_registry.html)

### Deployment Package

The deployment package is designed to be used on Edge Manageability Framework.
