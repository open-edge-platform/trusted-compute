{{/*
Secrets Volume Mounts
*/}}
{{- define "factory.volumeMountSecrets" -}}
- name: {{ include "factory.name" . }}-secrets
  mountPath: /etc/secrets/
  readOnly: true
{{- end }}


{{/*
Service Volume Mount Config
*/}}
{{- define "factory.volumeMountSvcConfig" -}}
- name: {{ include "factory.name" . }}-config
  mountPath: /etc/{{ .Values.service.directoryName }}
{{- end }}


{{/*
Service Volume Mount Logs
*/}}
{{- define "factory.volumeMountSvcLogs" -}}
- name: {{ include "factory.name" . }}-logs
  mountPath: /var/log/{{ .Values.service.directoryName }}
{{- end }}


{{/*
Service with DB Volume Mounts
*/}}
{{- define "factory.volumeMountsSvcDb" -}}
- name: {{ include "factory.name" . }}db-certs
  mountPath: /etc/postgresql/secrets/
  readOnly: true
{{ include "factory.volumeMountSecrets" . }}
{{- end }}


{{/*
Service with DB Volume Mounts
*/}}
{{- define "factory.volumeMountsSvcDbUpgrade" -}}
{{ include "factory.volumeMountSecrets" . }}
{{- end }}

{{/*
Service Base PV Volume Mount
*/}}
{{- define "factory.volumeMountsBasePv" -}}
- name: {{ include "factory.name" . }}-base
  mountPath: /{{ .Values.service.directoryName }}/
{{- end}}


{{/*
DB Service Volume Mounts
*/}}
{{- define "factory.volumeMountsDb" -}}
- name: {{ include "factory.name" . }}db-config
  mountPath: /etc/postgresql/config/
  readOnly: true
- name: {{ include "factory.name" . }}db-certs
  mountPath: /etc/postgresql/secrets/
  readOnly: true
- name: {{ include "factory.name" . }}db-data
  mountPath: /var/lib/postgresql/data/pgdata
{{- end}}
