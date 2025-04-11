{{/*
DB Certs Volume
*/}}
{{- define "factory.volumeDbCerts" -}}
- name: {{ include "factory.name" . }}db-certs
  secret:
    secretName: {{ include "factory.name" . }}db-certs
{{- end }}


{{/*
Base Secrets 
*/}}
{{- define "factory.volumeProjectedSecrets" -}}
- name: {{ include "factory.name" . }}-secrets
  projected:
    sources:
{{- end }}


{{/*
Credentials Volume
*/}}
{{- define "factory.volumeCredentials" -}}
- secret:
    name: {{ include "factory.name" . }}-credentials
{{- end }}

{{/*
DB Credentials Volume
*/}}
{{- define "factory.volumeDbCredentials" -}}
- secret:
    name: {{ include "factory.name" . }}db-credentials
{{- end }}

{{/*
AAS Bearer Token Volume
*/}}
{{- define "factory.volumeAasBearerToken" -}}
- secret:
    name: {{ include "factory.name" . }}-bearer-token
{{- end }}

{{/*
AAS Bootstrap token Volume
*/}}
{{- define "factory.volumeAasBootstrapToken" -}}
- secret:
    name: aas-token
{{- end }}


{{/*
K8s Token Volume
*/}}
{{- define "factory.volumeK8sToken" -}}
- secret:
    name: k8s-token
{{- end }}


{{/*
Config Service Volume
*/}}
{{- define "factory.volumeSvcConfig" -}}
- name: {{ include "factory.name" . }}-config
  persistentVolumeClaim:
    claimName: {{ include "factory.name" . }}-config
{{- end}}


{{/*
Logs Service Volume
*/}}
{{- define "factory.volumeSvcLogs" -}}
- name: {{ include "factory.name" . }}-logs
  persistentVolumeClaim:
    claimName: {{ include "factory.name" . }}-logs
{{- end}}

{{/*
Service with DB Volumes
*/}}
{{- define "factory.volumesSvcDb" -}}
{{- include "factory.volumeDbCerts" . }}
{{- end }}


{{/*
Base PV Service Volumes
*/}}
{{- define "factory.volumesBasePV" -}}
- name: {{ include "factory.name" . }}-base
  persistentVolumeClaim:
    claimName: {{ include "factory.name" . }}-base
{{- end}}


{{/*
AAS Service Volumes
*/}}
{{- define "factory.volumesSvcDbAas" -}}
{{- include "factory.volumeDbCerts" . }}
{{ include "factory.volumeProjectedSecrets" . }}
{{- include "factory.volumeDbCredentials" . | nindent 4 }}
{{ include "factory.volumeCredentials" . | indent 4 }}
{{ include "factory.volumeAasBootstrapToken" . | indent 4 }}    
{{- end}}

{{/*
DB Version Upgrade Service Volumes
*/}}
{{- define "factory.volumesSvcDbCredentials" -}}
{{ include "factory.volumeProjectedSecrets" . }}
{{- include "factory.volumeDbCredentials" . | nindent 4 }}
{{- end}}


{{/*
DB Service Volumes
*/}}
{{- define "factory.volumesDb" -}}
- name: {{ include "factory.name" . }}db-config
  configMap:
    name: {{ include "factory.name" . }}db
- name: {{ include "factory.name" . }}db-certs
  secret:
    secretName: {{ include "factory.name" . }}db-certs
    defaultMode: 0640
- name: {{ include "factory.name" . }}db-data
  persistentVolumeClaim:
    claimName: {{ include "factory.name" . }}db
{{ include "factory.volumesBasePV" . }}
{{- end}}


{{/*
Config Daemonset Volume
*/}}
{{- define "factory.volumeSvcConfigDaemonset" -}}
- name: {{ include "factory.name" . }}-config
  hostPath:
    path: /opt/{{ include "factory.name" . }}/{{ .Chart.AppVersion }}
    type: DirectoryOrCreate
{{- end}}


{{/*
Logs Daemonset Volume
*/}}
{{- define "factory.volumeSvcLogsDaemonset" -}}
- name: {{ include "factory.name" . }}-logs
  hostPath:
    path: /var/log/{{ include "factory.name" . }}
    type: DirectoryOrCreate
{{- end}}
