{{/*
Labels for Chart
*/}}
{{- define "factory.labelsChart" -}}
helm.sh/chart: {{ include "factory.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}


{{/*
Labels for Service
*/}}
{{- define "factory.labelsSvc" -}}
app.kubernetes.io/name: {{ include "factory.name" . }}
{{- end }}


{{/*
Labels for DB
*/}}
{{- define "factory.labelsDb" -}}
app.kubernetes.io/name: {{ include "factory.name" . }}db
{{- end }}


{{/*
Selector Labels for Service
*/}}
{{- define "factory.labelsSvcSelector" -}}
app.kubernetes.io/name: {{ include "factory.name" . }}
{{- end }}


{{/*
Selector Labels for DB
*/}}
{{- define "factory.labelsDbSelector" -}}
app.kubernetes.io/name: {{ include "factory.name" . }}db
{{- end }}
