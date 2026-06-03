{{/*
Initialize HVS service password once per render so all templates reuse the same value.
*/}}
{{- define "hvs.initServicePassword" -}}
{{- if not .Values.secret.servicePassword -}}
{{- $hvs_service_password := randAlphaNum 16 -}}
{{- $_ := set .Values.secret "servicePassword" $hvs_service_password -}}
{{- end -}}
{{- end -}}