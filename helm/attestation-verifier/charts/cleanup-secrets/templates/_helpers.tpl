{{/*
Expand the name of the chart.
*/}}
{{- define "cleanup-secrets.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "cleanup-secrets.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "cleanup-secrets.labels" -}}
helm.sh/chart: {{ include "cleanup-secrets.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ include "cleanup-secrets.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "cleanup-secrets.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cleanup-secrets.name" . }}
{{- end }}