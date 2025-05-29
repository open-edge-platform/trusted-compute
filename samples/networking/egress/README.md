<!---
  SPDX-FileCopyrightText: (C) 2025 Intel Corporation
  SPDX-License-Identifier: Apache-2.0
-->

## Helm Chart: curl-loop

This Helm chart deploys a container using `curlimages/curl` that continuously curls http://httpbin.org/headers every 5 seconds using the following configuration:


To use the chart package it and upload it to your local OCI registry:

```bash
helm package helm
```

Upload the package to your local OCI registry following the instructions
[here](https://docs.openedgeplatform.intel.com/edge-manage-docs/main/user_guide/package_software/push_registry.html)

### Deployment Package

The deployment package is designed to be used on Edge Manageability Framework.
