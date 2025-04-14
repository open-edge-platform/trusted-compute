{{/*
Expand the name of the chart.
*/}}
{{- define "cleanup-host.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cleanup-host.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cleanup-host.labels" -}}
helm.sh/chart: {{ include "cleanup-host.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ include "cleanup-host.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cleanup-host.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cleanup-host.name" . }}
{{- end }}