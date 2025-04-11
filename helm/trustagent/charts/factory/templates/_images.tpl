{{/*
Service container Image
*/}}
{{- define "factory.imageContainer" }}
image: {{ .Values.image.svc.name }}:{{.Chart.AppVersion }}
imagePullPolicy: {{ .Values.image.svc.pullPolicy }}
{{- end }}


{{/*    
Init container Image
*/}}
{{- define "factory.imageInitContainer" }}
image: {{ .Values.image.svc.initName }}:{{.Chart.AppVersion }}
{{- end }}


{{/*
DB container Image
*/}}
{{- define "factory.imageDb" }}
image: {{ .Values.image.db.name }}
imagePullPolicy: {{ .Values.image.db.pullPolicy }}
{{- end }}
