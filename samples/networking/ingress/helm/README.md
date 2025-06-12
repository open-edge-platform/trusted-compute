<!---
  SPDX-FileCopyrightText: (C) 2025 Intel Corporation
  SPDX-License-Identifier: BSD-3-Clause
-->

# httpbin-chart

Helm chart to install [httpbingo.org](https://httpbingo.org) on Kubernetes

This chart adds an Envoy proxy sidecar that sets the `Authorization` header removed by Kube API proxy.

