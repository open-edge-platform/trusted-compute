{{/*
Args for Db
*/}}
{{- define "factory.argsDb" -}}
- -c
- hba_file=/etc/postgresql/config/pg_hba.conf
- -c
- config_file=/etc/postgresql/config/postgresql.conf
{{- end }}