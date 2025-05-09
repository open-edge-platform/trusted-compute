
Global-admin-generator
===========

A Helm chart for creating Global Admin User Account


## Configuration

The following table lists the configurable parameters of the Global-admin-generator chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `nameOverride` | The name for global admin generator database chart (Default: .Chart.Name) | `""` |
| `dependentServices.aas` |  | `"aas"` |
| `securityContext.aasManager.runAsUser` |  | `1200` |
| `securityContext.aasManager.runAsGroup` |  | `1200` |
| `securityContext.aasManager.capabilities.drop` |  | `["all"]` |
| `securityContext.aasManager.allowPrivilegeEscalation` |  | `false` |
| `securityContext.aasManagerInit.fsGroup` |  | `1200` |
| `aas.url` |  | `null` |
| `aas.secret.adminUsername` | Admin Username for AAS | `null` |
| `aas.secret.adminPassword` | Admin Password for AAS | `null` |
| `image.svc.pullPolicy` | The pull policy for pulling from container registry | `"Always"` |
| `image.svc.imagePullSecret` | The image pull secret for authenticating with image registry, can be left empty if image registry does not require authentication | `null` |
| `image.svc.initName` |  | `"<user input>"` |
| `image.aasManager.name` | The image registry where AAS Manager image is pushed<br> (**REQUIRED**) | `"<user input>"` |
| `image.aasManager.pullPolicy` | The pull policy for pulling from container registry for AAS Manager<br> (Allowed values: `Always`/`IfNotPresent`) | `"Always"` |
| `image.aasManager.imagePullSecret` | The image pull secret for authenticating with image registry, can be left empty if image registry does not require authentication | `null` |
| `secret.globalAdminUsername` |  | `null` |
| `secret.globalAdminPassword` |  | `null` |
| `service.aas.containerPort` | The containerPort on which AAS can listen | `8444` |
| `service.aas.port` | The externally exposed NodePort on which AAS can listen to external traffic | `30444` |
| `services_list` | Services list for global admin token generation. Accepted values HVS, WLS, WLA, KBS, TA | `[null, null]` |
| `factory.nameOverride` |  | `""` |



---
_Documentation generated by [Frigate](https://frigate.readthedocs.io)._

