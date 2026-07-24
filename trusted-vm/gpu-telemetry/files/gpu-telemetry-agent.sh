#!/bin/bash
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# GPU telemetry agent for kata guests. Collects GPU stats via qmassa and
# emits InfluxDB line protocol over HTTP to a configurable collector endpoint.
#
# Metrics emitted:
#     gpu_engine_usage,engine=<e>,type=<e>,host=<h>,gpu_id=<n> usage=<v> <ts_ns>
#     gpu_frequency,type=cur_freq,host=<h>,gpu_id=<n> value=<v> <ts_ns>
#     gpu_power,type=<k>,host=<h>,gpu_id=<n> value=<v> <ts_ns>
#
# The collector endpoint is configured via PUSH_HOST/PUSH_PORT/PUSH_PATH.
# Any HTTP listener that accepts InfluxDB line protocol (Telegraf, Victoria
# Metrics, InfluxDB, etc.) can be used as the target.
#
# Implemented in bash + static jq.
#
# Guest install paths:
#   /usr/local/bin/qmassa            (GPU stats tool)
#   /usr/local/bin/jq                (static jq)
#   /usr/local/bin/gpu-telemetry-agent.sh

set -euo pipefail

log() { echo "[gpu-telemetry] $*" >&2; }

# Collector endpoint must be supplied via kata kernel_params annotation:
#   push_host=<ip> push_port=<port> push_path=<path>
# The agent exits cleanly if any are absent.
# Read cmdline as a single line, split on spaces, and take the first matching
# key to avoid multi-match newlines from grep -o.
_cmdline_val() {
  local key="$1"
  local token
  for token in $(cat /proc/cmdline 2>/dev/null); do
    case "${token}" in "${key}="*) echo "${token#"${key}="}"; return;; esac
  done
}
PUSH_HOST="$(_cmdline_val push_host)"
PUSH_PORT="$(_cmdline_val push_port)"
PUSH_PATH="$(_cmdline_val push_path)"

if [ -z "${PUSH_HOST}" ]; then
  log "PUSH_HOST not configured; telemetry disabled."
  exit 0
fi
if [ -z "${PUSH_PORT}" ]; then
  log "PUSH_PORT not configured; telemetry disabled."
  exit 0
fi
if ! [[ "${PUSH_PORT}" =~ ^[0-9]+$ ]] || (( PUSH_PORT < 1 || PUSH_PORT > 65535 )); then
  log "PUSH_PORT is invalid (${PUSH_PORT}); telemetry disabled."
  exit 0
fi
if [ -z "${PUSH_PATH}" ]; then
  log "PUSH_PATH not configured; telemetry disabled."
  exit 0
fi
if [[ "${PUSH_PATH}" != /* ]] || [[ "${PUSH_PATH}" == *[[:space:]]* ]]; then
  log "PUSH_PATH must start with '/' and contain no whitespace: '${PUSH_PATH}'; telemetry disabled."
  exit 0
fi
if ! [[ "${PUSH_HOST}" =~ ^[A-Za-z0-9.-]+$ ]]; then
  log "PUSH_HOST must be an IP/hostname with only [A-Za-z0-9.-]: '${PUSH_HOST}'; telemetry disabled."
  exit 0
fi
INTERVAL_MS="${COLLECT_INTERVAL_MS:-1000}"
if ! [[ "${INTERVAL_MS}" =~ ^[0-9]+$ ]] || (( INTERVAL_MS < 1 )); then
  log "COLLECT_INTERVAL_MS is invalid (${INTERVAL_MS}); telemetry disabled."
  exit 0
fi
QMASSA_BIN="${QMASSA_BIN:-/usr/local/bin/qmassa}"
JQ_BIN="${JQ_BIN:-/usr/local/bin/jq}"
[[ -x "$QMASSA_BIN" ]] || { log "QMASSA_BIN not executable: $QMASSA_BIN"; exit 1; }
[[ -x "$JQ_BIN" ]] || { log "JQ_BIN not executable: $JQ_BIN"; exit 1; }
# The guest has no `hostname` binary; bash sets $HOSTNAME natively. Fall back to
# /etc/hostname then a literal so the influx `host=` tag is never empty.
HOSTTAG="${METRICS_HOSTNAME:-${HOSTNAME:-$(cat /etc/hostname 2>/dev/null || echo kata-guest)}}"
RUNDIR="/run/gpu-telemetry"
FIFO="${RUNDIR}/qmassa.fifo"

# Wait up to 60s for a GPU render node (hot-plugged after boot).
for _ in {1..60}; do
  ls /dev/dri/renderD* >/dev/null 2>&1 && break
  sleep 1
done
ls /dev/dri/renderD* >/dev/null 2>&1 || { log "no GPU render node present; exiting."; exit 0; }

# Remove any stale path that is not a FIFO; then create the FIFO.
[ -p "$FIFO" ] || { rm -f "$FIFO"; mkfifo "$FIFO"; }

# jq program that parses qmassa JSON output into InfluxDB line protocol.
JQ_FILTER='
  ( now * 1000000000 | floor ) as $ts
  | .devs_state[]?
  | ((.dev_nodes // "") | capture("renderD(?<n>[0-9]+)")? | .n | tonumber) as $rd
  | select($rd >= 128)
  | ($rd - 128) as $gid
  | .dev_stats as $s
  | (
      ( $s.eng_usage // {} | to_entries[] | select((.value|length) > 0)
        | "gpu_engine_usage,engine=\(.key),type=\(.key),host=\($h),gpu_id=\($gid) usage=\(.value[-1]) \($ts)" ),
      ( if (($s.freqs|length) > 0) and ($s.freqs[-1]|type=="array")
             and (($s.freqs[-1]|length) > 0) and ($s.freqs[-1][0].cur_freq != null)
        then "gpu_frequency,type=cur_freq,host=\($h),gpu_id=\($gid) value=\($s.freqs[-1][0].cur_freq) \($ts)"
        else empty end ),
      ( if ($s.power|length) > 0
        then ( $s.power[-1] | to_entries[]
               | "gpu_power,type=\(.key),host=\($h),gpu_id=\($gid) value=\(.value) \($ts)" )
        else empty end )
    )
'

post() {
  local body="$1"
  [ -n "$body" ] || return 0
  
  {
    printf 'POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s' \
      "$PUSH_PATH" "$PUSH_HOST" "${#body}" "$body"
  } | timeout 10s bash -c 'cat >"/dev/tcp/$1/$2"' _ "$PUSH_HOST" "$PUSH_PORT" 2>/dev/null || {
    log "POST to ${PUSH_HOST}:${PUSH_PORT} failed or timed out"
    return 1
  }
}

log "GPU detected; pushing to http://${PUSH_HOST}:${PUSH_PORT}${PUSH_PATH} (InfluxDB line protocol)"

"$QMASSA_BIN" --no-tui -m "$INTERVAL_MS" --to-json "$FIFO" &
QPID=$!
trap 'kill "$QPID" 2>/dev/null; wait "$QPID" 2>/dev/null || true' EXIT
sleep 1
if ! kill -0 "$QPID" 2>/dev/null; then
  log "qmassa exited immediately (pid $QPID); check binary and GPU state"
  exit 1
fi

exec 3<"$FIFO"
while IFS= read -r line <&3; do
  [ -n "$line" ] || continue
  lp="$(printf '%s' "$line" | "$JQ_BIN" -rc --arg h "$HOSTTAG" "$JQ_FILTER" 2>/dev/null)" || continue
  if [ -n "$lp" ]; then
    post "$lp" || log "push failed; continuing"
  fi
done

wait "$QPID" || true
log "qmassa exited; restarting via systemd."
exit 1
