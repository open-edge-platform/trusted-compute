{{/*
Service container Image
*/}}
{{- define "factory.imageContainer" }}
{{- if .Values.global }}
image: {{ .Values.image.name }}:{{.Chart.AppVersion }}
imagePullPolicy: {{ .Values.global.image.pullPolicy }}
{{- else }}
image: {{ .Values.image.svc.name }}:{{.Chart.AppVersion }}
imagePullPolicy: {{ .Values.image.svc.pullPolicy }}
{{- end }}
{{- end }}


{{/*    
Init container Image
*/}}
{{- define "factory.imageInitContainer" }}
{{- if .Values.global }}
image: {{ .Values.global.image.initName }}:{{.Chart.AppVersion }}
{{- else }}
image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
{{- end }}
{{- end }}


{{/*
DB container Image
*/}}
{{- define "factory.imageDb" }}
image: {{ .Values.image.db.name }}
{{- if .Values.global }}
imagePullPolicy: {{ .Values.global.image.pullPolicy }}
{{- else }}
imagePullPolicy: {{ .Values.image.db.pullPolicy }}
{{- end }}
{{- end }}
