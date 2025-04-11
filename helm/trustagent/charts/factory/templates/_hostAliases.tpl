{{/*
Host Aliases
*/}}
{{- define "factory.hostAliases" -}}
{{- if .Values.global }}
{{- if .Values.global.hostAliasEnabled }}
{{- toYaml .Values.global.aliases }}
{{- end }}
{{- else if .Values.hostAliasEnabled }}
{{- toYaml .Values.aliases }}
{{- end }}
{{- end }}