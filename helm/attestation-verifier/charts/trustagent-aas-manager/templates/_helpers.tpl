{{/*
Expand the name of the chart.
*/}}
{{- define "trustagent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "trustagent.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "trustagent.labels" -}}
helm.sh/chart: {{ include "nats.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ include "trustagent.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "trustagent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "trustagent.name" . }}
{{- end }}
