
Nats
===========

A Helm chart for Installing NATS server


## Configuration

The following table lists the configurable parameters of the Nats chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `nameOverride` | The name for NATS chart<br> (Default: `.Chart.Name`) | `""` |
| `controlPlaneHostname` | K8s control plane IP/Hostname<br> (**REQUIRED**) | `"<user input>"` |
| `dependentServices.cms` |  | `"cms"` |
| `dependentServices.aas` |  | `"aas"` |
| `image.svc.name` | The name of the NATS image <br> (**REQUIRED**) | `"nats:2.7.2-alpine3.15"` |
| `image.svc.pullPolicy` | The pull policy for pulling from container registry for NATS<br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `securityContext.init.fsGroup` |  | `1200` |
| `securityContext.nats.runAsUser` |  | `1200` |
| `securityContext.nats.runAsGroup` |  | `1200` |
| `service.directoryName` |  | `"nats"` |
| `service.cms.containerPort` | The containerPort on which CMS can listen | `8445` |
| `service.aas.containerPort` | The containerPort on which AAS can listen | `8444` |
| `service.aas.port` | The externally exposed NodePort on which AAS can listen to external traffic | `30444` |
| `service.natsCluster.name` |  | `"cluster"` |
| `service.natsCluster.containerPort` | The containerPort on which NATS can listen to traffic | `6222` |
| `service.natsClient.name` |  | `"client"` |
| `service.natsClient.containerPort` | The containerPort on which NATS can listen to traffic | `4222` |
| `service.natsClient.port` | The externally exposed NodePort on which NATS can listen to external traffic | `30222` |



---
_Documentation generated by [Frigate](https://frigate.readthedocs.io)._

