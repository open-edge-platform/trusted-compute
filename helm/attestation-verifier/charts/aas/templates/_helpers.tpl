{{/*
Common labels for CMS INIT
*/}}
{{- define "cms-init.labels" -}}
helm.sh/chart: {{ .Values.dependentServices.cms }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/name: {{ .Values.dependentServices.cms }}-init
{{- end }}


{{/*
Selector labels for CMS INIT
*/}}
{{- define "cms-init.selectorLabels" -}}
app.kubernetes.io/name: {{ .Values.dependentServices.cms }}-init
{{- end }}
