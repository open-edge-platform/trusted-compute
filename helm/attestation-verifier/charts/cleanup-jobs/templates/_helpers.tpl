{{/*
Expand the name of the chart.
*/}}
{{- define "cleanup-jobs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cleanup-jobs.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cleanup-jobs.labels" -}}
helm.sh/chart: {{ include "cleanup-jobs.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ include "cleanup-jobs.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cleanup-jobs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cleanup-jobs.name" . }}
{{- end }}