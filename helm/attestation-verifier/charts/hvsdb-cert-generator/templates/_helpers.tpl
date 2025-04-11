{{/*
Expand the name of the chart.
*/}}
{{- define "hvsdb-cert-generator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "hvsdb-cert-generator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "hvsdb-cert-generator.labels" -}}
helm.sh/chart: {{ include "hvsdb-cert-generator.chart" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ include "hvsdb-cert-generator.name" . }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "hvsdb-cert-generator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "hvsdb-cert-generator.name" . }}
{{- end }}